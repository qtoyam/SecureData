using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Reflection;

using SecureData.Cryptography.Hash;
using SecureData.Storage.Exceptions;
using SecureData.Storage.Helpers;

//TODO:0 const -> static?
namespace SecureData.Storage.Models.Abstract;

public abstract class Data
{
	public const uint NullId = 0U;
	public const long DeletedFlag = 1U << 31;

	public bool IsLoaded { get; private set; }

	private const uint InitedState = uint.MaxValue;

	private const int HashStart = Layout.DataTypeOffset;
	public static readonly int DividableBy = Cryptography.SymmetricEncryption.AesCtr.BlockSize;

	private static uint _lastId = NullId;
	private static uint GetId()
	{
		uint id = Interlocked.Increment(ref _lastId);
		if (id == uint.MaxValue)
		{
			throw new UnexpectedException("Id overflow.");
		}
		return id;
	}

	public bool IsMutable { get; private set; }
	private uint _state;

	/// <summary>
	/// Count of changes in object since last flush.
	/// </summary>
	public uint Changes { get; private set; }

	public bool HasChanges => Changes > 0;

	private static class Layout
	{
		public const int HashOffset = 0;
		public const int HashSize = 32;

		public const int DataTypeOffset = HashOffset + HashSize;
		public const int DataTypeSize = sizeof(long);

		public const int IdOffset = DataTypeOffset + DataTypeSize;
		public const int IdSize = sizeof(uint);

		public const int ParentIdOffset = IdOffset + IdSize;
		public const int ParentIdSize = sizeof(uint);

		public const int TimeStampOffset = ParentIdOffset + ParentIdSize;
		public const int TimeStampSize = sizeof(long); //DateTime

		public const int LastEditOffset = TimeStampOffset + TimeStampSize;
		public const int LastEditSize = sizeof(long); //DateTime

		public const int NameOffset = LastEditOffset + LastEditSize;
		public const int NameSize = 128;

		public const int DescriptionOffset = NameOffset + NameSize;
		public const int DescriptionSize = 256;
	}
	protected const int SizeConst = Layout.DescriptionOffset + Layout.DescriptionSize;
	protected const long DataTypeConst = DeletedFlag;
	protected const int SensitiveOffsetConst = SizeConst;

	/// <summary>
	/// Init non-sensitive data.
	/// </summary>
	/// <param name="raw"></param>
	protected Data(ReadOnlySpan<byte> raw)
	{
		Debug.Assert(raw.Length >= Size);
		//skip id (inited in Create)
		BinaryHelper.ReadBytes(raw.Slice(Layout.HashOffset, Layout.HashSize), _hash.Span);
		TimeStamp = BinaryHelper.ReadDateTime(raw.Slice(Layout.TimeStampOffset, Layout.TimeStampSize));
		_state = BinaryHelper.ReadUInt32(raw.Slice(Layout.ParentIdOffset, Layout.ParentIdSize));
		_lastEdit = BinaryHelper.ReadDateTime(raw.Slice(Layout.LastEditOffset, Layout.LastEditSize));
		_name = BinaryHelper.ReadString(raw.Slice(Layout.NameOffset, Layout.NameSize));
		_description = BinaryHelper.ReadString(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize));

		IsLoaded = false;
		IsMutable = false;
		//_state = InitedState; dont do it becauze _state will be used to find parent
	}
	/// <summary>
	/// Set defaults.
	/// </summary>
	public Data()
	{
		_name = _description = string.Empty;
		IsLoaded = true;
		IsMutable = true;
		_state = NullId;
	}

	[MemberNotNullWhen(true, nameof(Parent))]
	public bool HasParent => Parent is not null;

	#region DB
	#region Private write-access
	private readonly Memory<byte> _hash = new byte[Layout.HashSize];
	private FolderData? _parent;
	private DateTime _lastEdit;
	private string _name;
	private string _description;
	#endregion
	public ReadOnlyMemory<byte> Hash => _hash;
	public abstract long DataType { get; }
	public uint Id { get; private set; } = NullId;
	public FolderData? Parent
	{
		get => _parent;
		set => Set(ref _parent, value);
	}
	public DateTime TimeStamp { get; private set; }
	public DateTime LastEdit
	{
		get => _lastEdit;
		private set => Set(ref _lastEdit, value);
	}
	public string Name
	{
		get => _name;
		set => Set(ref _name, value);
	}
	public string Description
	{
		get => _description;
		set => Set(ref _description, value);
	}
	#endregion

	internal void ClearSensitive()
	{
		if (IsLoaded)
		{
			ClearSensitiveCore();
			IsLoaded = false;
		}
	}
	internal void LoadSensitive(ReadOnlySpan<byte> sensitiveBytes)
	{
		if (!IsLoaded)
		{
			LoadSensitiveCore(sensitiveBytes);
			IsLoaded = true;
		}
	}

	protected abstract void ClearSensitiveCore();
	protected abstract void LoadSensitiveCore(ReadOnlySpan<byte> sensitiveBytes);


	/// <summary>
	/// Total size.
	/// </summary>
	public abstract int Size { get; }
	public virtual int SensitiveOffset => Size;

	public bool HasSensitive => SensitiveOffset < Size;
	public int SensitiveSize => Size - SensitiveOffset;

	/// <summary>
	/// Initializes new data instance.
	/// </summary>
	internal void FinishInit()
	{
		EnsureNotInited();
		//set constant values
		Id = GetId();
		TimeStamp = DateTime.Now;
		LastEdit = TimeStamp; //created = edited, not constant
							  //update states
		_state = InitedState; //new instance is initialized
		IsMutable = false; //immutable
		IsLoaded = true; //loaded
	}

	internal void Flush(Span<byte> raw)
	{
		if (raw.Length < Size)
		{
			throw new ArgumentException("Buffer less than data size.", nameof(raw));
		}
		Debug.Assert(HasChanges, "Flush called without changes");
		EnsureLoaded();
		EnsureImmutable();
		BinaryHelper.Write(raw.Slice(Layout.DataTypeOffset, Layout.DataTypeSize), DataType);
		BinaryHelper.Write(raw.Slice(Layout.IdOffset, Layout.IdSize), Id);
		BinaryHelper.Write(raw.Slice(Layout.ParentIdOffset, Layout.ParentIdSize), HasParent ? Parent.Id : NullId);
		BinaryHelper.Write(raw.Slice(Layout.TimeStampOffset, Layout.TimeStampSize), TimeStamp);
		BinaryHelper.Write(raw.Slice(Layout.LastEditOffset, Layout.LastEditSize), LastEdit);
		BinaryHelper.WriteStringWithRNG(raw.Slice(Layout.NameOffset, Layout.NameSize), Name);
		BinaryHelper.WriteStringWithRNG(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize), Description);
		FlushCore(raw);
		SHA256.ComputeHash(raw.Slice(HashStart), _hash.Span); //compute and update hash
		BinaryHelper.Write(raw.Slice(Layout.HashOffset, Layout.HashSize), Hash.Span);
		Changes = 0;
	}

	internal void Unfreeze()
	{
		EnsureLoaded();
		EnsureImmutable();
		IsMutable = true;
	}
	internal void Freeze()
	{
		EnsureLoaded();
		EnsureMutable();
		if (HasChanges)
		{
			LastEdit = DateTime.Now;
		}
		IsMutable = false;
	}

	/// <summary>
	/// Flushes only derived class data.
	/// </summary>
	/// <param name="raw"></param>
	protected abstract void FlushCore(Span<byte> raw);

	protected T GetSensitive<T>(ref T? field)
	{
		EnsureLoaded();
		return field ?? throw new UnexpectedException("Data is loaded but sensitive field is null");
	}
	/// <summary>
	/// Use this to set back-field of any raw memory related property. 
	/// Ensures object visiblity and increment changes count.
	/// </summary>
	/// <typeparam name="T">
	/// Field type.
	/// </typeparam>
	/// <param name="field">
	/// Field reference.
	/// </param>
	/// <param name="newValue">
	/// New value to set into <paramref name="field"/>.
	/// </param>
	protected void Set<T>(ref T field, T newValue)
	{
		EnsureLoaded();
		EnsureMutable();
		if (!Equals(field, newValue))
		{
			field = newValue;
			++Changes;
		}
	}

	protected void EnsureNoChanges()
	{
		if (Changes != 0)
		{
			throw new InvalidOperationException("Object has changes.");
		}
	}
	protected void EnsureNotInited()
	{
		if (_state == InitedState || Id != NullId)
		{
			throw new InvalidOperationException("Object is inited.");
		}
	}
	protected void EnsureMutable()
	{
		if (!IsMutable)
		{
			throw new InvalidOperationException("Data is immutable");
		}
	}
	protected void EnsureImmutable()
	{
		if (IsMutable)
		{
			throw new InvalidOperationException("Data is mutable");
		}
	}
	protected void EnsureLoaded()
	{
		if (HasSensitive && !IsLoaded)
		{
			throw new DataLoadedException(true);
		}
	}
	protected void EnsureUnloaded()
	{
		if (HasSensitive && IsLoaded)
		{
			throw new DataLoadedException(false);
		}
	}

	internal static void OrganizeHierarchy(DataSet dataSet)
	{
		foreach (var data in dataSet)
		{
			uint parentId = data._state;
			if (parentId != NullId)
			{
				FolderData parent = (FolderData?)dataSet[parentId]
					?? throw new UnexpectedException("ParentId is not parent.");
				data._parent = parent;
				parent.Add(data);
			}
		}
	}

	internal class Metadata
	{
		private delegate Data DataCreator(ReadOnlySpan<byte> data);
		private record DataMetadata(long DataType, int Size, int PublicSize, DataCreator Creator);
		private readonly DataMetadata[] _dataMetadata;

		private DataMetadata this[long dataType]
		{
			get
			{
				for (int i = 0; i < _dataMetadata.Length; i++)
				{
					if (_dataMetadata[i].DataType == dataType)
					{
						return _dataMetadata[i];
					}
				}
				throw new ArgumentOutOfRangeException(nameof(dataType), "Can not find data metadata");
			}
		}

		public Metadata()
		{
			var type_Data = typeof(Data);
			List<DataMetadata> metadata = new();
			ParameterExpression param_Raw = Expression.Parameter(typeof(ReadOnlySpan<byte>));
			Type[] params_Ctor = new Type[] { typeof(ReadOnlySpan<byte>) };
			foreach (var a in AppDomain.CurrentDomain
				.GetAssemblies()
				.Where(x => !x.IsDynamic))
			{
				foreach (var t in a
					.ExportedTypes
					.Where(x => x.IsClass && !x.IsAbstract && x.IsSubclassOf(type_Data))
					)
				{
					//data type
					long dataTypeConst = GetConstFieldValue<long>(t, nameof(DataTypeConst));
					if ((dataTypeConst & DeletedFlag) == DeletedFlag)
					{
						throw new UnexpectedException(
							   $"Type \"{t.FullName}\", {nameof(DataTypeConst)} contains {nameof(DeletedFlag)}.");
					}

					//size
					int sizeConst = GetConstFieldValue<int>(t, nameof(SizeConst));
					if ((sizeConst % DividableBy) != 0)
					{
						throw new UnexpectedException(
							   $"Type \"{t.FullName}\", {nameof(SizeConst)} value not dividable by {nameof(DividableBy)}.");
					}

					//sensitive offset
					int sensitiveOffsetConst = GetConstFieldValue<int>(t, nameof(SensitiveOffsetConst));
					if ((sensitiveOffsetConst % DividableBy) != 0)
					{
						throw new NotImplementedException(
							   $"Type \"{t.FullName}\", {nameof(SensitiveOffsetConst)} value not dividable by {nameof(DividableBy)}.");
					}

					var ctor = t.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, params_Ctor)
						?? throw new UnexpectedException($"Type \"{t.FullName}\", not implemented protected constructor.");
					var creator = Expression.Lambda<DataCreator>(
						   Expression.New(ctor, param_Raw), param_Raw
						   ).Compile();
					metadata.Add(new(dataTypeConst, sizeConst, sensitiveOffsetConst, creator));
				}
			}
			_dataMetadata = metadata.ToArray();
			for (int i = 0; i < _dataMetadata.Length - 1; i++)
			{
				var currentDataType = _dataMetadata[i].DataType;
				for (int j = i + 1; j < _dataMetadata.Length; j++)
				{
					var comparedDataType = _dataMetadata[j].DataType;
					if (currentDataType == comparedDataType)
					{
						throw new InvalidOperationException($"Multiple data types have same data type identifier ({currentDataType})");
					}
				}
			}
		}

		public Data? Create(ReadOnlySpan<byte> buffer, Span<byte> tmpHash, out int readBytes)
		{
			long dataType = BinaryHelper.ReadInt64(buffer.Slice(Layout.DataTypeOffset, Layout.DataTypeSize));
			bool deleted = (dataType & DeletedFlag) == DeletedFlag;
			dataType &= ~DeletedFlag; //remove ONLY deleted flag
			DataMetadata type = this[dataType];
			if (buffer.Length < type.Size)
			{
				throw new ArgumentOutOfRangeException(nameof(buffer));
			}
			buffer = buffer.Slice(0, type.Size);
			uint id = BinaryHelper.ReadUInt32(buffer.Slice(Layout.IdOffset, Layout.IdSize));
			if (id > _lastId)
			{
				_lastId = id;
			}
			readBytes = type.Size;
			if (deleted)
			{
				return null;
			}
			Data data = type.Creator(buffer);
			data.Id = id;
			Span<byte> s_actualHash = tmpHash.Slice(0, SHA256.HashSize);
			SHA256.ComputeHash(buffer.Slice(HashStart), s_actualHash);
			if (!MemoryHelper.Compare(data.Hash.Span, s_actualHash))
			{
				throw new DataWrongHashException(data);
			}
			return data;
		}

		private static TField GetConstFieldValue<TField>(Type type, string fieldName)
		{
			var field = type.GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Static)
						?? throw new UnexpectedException($"Type \"{type.FullName}\", not implemented {fieldName}.");
			return (TField)field.GetValue(null)!;
		}
	}
}
