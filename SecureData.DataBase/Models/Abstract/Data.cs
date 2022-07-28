using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Reflection;

using SecureData.Cryptography.Hash;
using SecureData.DataBase.Helpers;
using SecureData.DataBase.Services;
using SecureData.DataBase.Exceptions;

//TODO:0 const -> static
namespace SecureData.DataBase.Models.Abstract;

public abstract class Data
{
	public const uint NullId = 0U;
	public const long DeletedFlag = 1U << 31;
	public const int MinSizeToRead = Layout.DataTypeOffset + Layout.DataTypeSize;

	private const int HashStart = Layout.DataTypeOffset;
	public static readonly int DividableBy = Cipher.BlockSize;

	private static uint _lastId = NullId;
	private static uint GetId()
	{
		uint id = Interlocked.Increment(ref _lastId);
		if (id == uint.MaxValue)
		{
			throw new InvalidOperationException("Id overflow.");
		}
		return id;
	}

	private delegate Data DataCreator(ReadOnlySpan<byte> data);
	private readonly static (long DataType, int Size, DataCreator Creator)[] Types;

	static Data()
	{
		int value_SizeConst;
		var type_Data = typeof(Data);
		List<(long DataType, int Size, DataCreator Creator)> types = new();
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
				var field_DataTypeConst = t.GetField(nameof(DataTypeConst), BindingFlags.NonPublic | BindingFlags.Static)
					?? throw new NotImplementedException($"Type \"{t.FullName}\", not implemented const field {nameof(DataTypeConst)}.");
				long value_DataTypeConst = (long)field_DataTypeConst.GetValue(null)!;
				if (value_DataTypeConst == DeletedFlag)
				{
					throw new NotImplementedException($"Type \"{t.FullName}\", const field {nameof(DataTypeConst)} can not be equals to {nameof(DeletedFlag)}. It is reserved.");
				}
				//size
				var field_SizeConst = t.GetField(nameof(SizeConst), BindingFlags.NonPublic | BindingFlags.Static)
					?? throw new NotImplementedException($"Type \"{t.FullName}\", not implemented const field {nameof(SizeConst)}.");
				value_SizeConst = (int)field_SizeConst.GetValue(null)!;
				if ((value_SizeConst % DividableBy) != 0)
				{
					throw new NotImplementedException($"Type \"{t.FullName}\", const field {nameof(SizeConst)} value not dividable by {nameof(DividableBy)}.");
				}

				var ctor = t.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, params_Ctor)
					?? throw new NotImplementedException($"Type \"{t.FullName}\", not implemented protected constructor with {nameof(ReadOnlySpan<byte>)} as parameter.");
				var creator = Expression.Lambda<DataCreator>(
					   Expression.New(ctor, param_Raw), param_Raw
					   ).Compile();
				types.Add(new(value_DataTypeConst, value_SizeConst, creator));
			}
		}
		Types = types.ToArray();
		for (int i = 0; i < Types.Length - 1; i++)
		{
			var currentDataType = Types[i].DataType;
			for (int j = i + 1; j < Types.Length; j++)
			{
				var comparedDataType = Types[j].DataType;
				if (currentDataType == comparedDataType)
				{
					throw new InvalidOperationException($"Multiple data types have same data type identifier ({currentDataType})");
				}
			}
		}
	}

	private uint _state = NullId;

	/// <summary>
	/// Count of changes in object since last flush.
	/// </summary>
	public int Changes { get; private set; }

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

	protected Data(ReadOnlySpan<byte> raw)
	{
		Debug.Assert(raw.Length >= Size);
		BinaryHelper.ReadBytes(raw.Slice(Layout.HashOffset, Layout.HashSize), _hash.Span);
		TimeStamp = BinaryHelper.ReadDateTime(raw.Slice(Layout.TimeStampOffset, Layout.TimeStampSize));
		//skip parent
		_lastEdit = BinaryHelper.ReadDateTime(raw.Slice(Layout.LastEditOffset, Layout.LastEditSize));
		_name = BinaryHelper.ReadString(raw.Slice(Layout.NameOffset, Layout.NameSize));
		_description = BinaryHelper.ReadString(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize));
	}
	protected Data()
	{
		_name = string.Empty;
		_description = string.Empty;
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

	public abstract void ClearSensitive();
	public abstract void LoadSensitive(ReadOnlySpan<byte> rawBytes);


	/// <summary>
	/// Total size.
	/// </summary>
	public abstract int Size { get; }
	public abstract int SensitiveOffset { get; }

	public bool HasSensitiveContent => SensitiveOffset < Size;

	/// <summary>
	/// Try to create initialized <see cref="Data"/> from <paramref name="buffer"/>.
	/// </summary>
	/// <param name="buffer"></param>
	/// <param name="data"></param>
	/// <param name="readBytes">
	/// Byts processed in <paramref name="buffer"/>.
	/// </param>
	/// <returns>
	/// <see langword="true"/> if created, otherwise <see langword="false"/>.
	/// </returns>
	internal static bool TryCreateFromBuffer(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out Data? data, out int readBytes)
	{
		Debug.Assert(buffer.Length >= MinSizeToRead);
		long dataType = BinaryHelper.ReadInt64(buffer.Slice(Layout.DataTypeOffset, Layout.DataTypeSize));
		bool deleted = (dataType & DeletedFlag) == DeletedFlag;
		dataType &= ~DeletedFlag; //remove ONLY deleted flag
		var type = Types.Single(x => x.DataType == dataType);
		if (type.Size > buffer.Length)
		{
			data = null;
			readBytes = 0;
			return false;
		}
		readBytes = type.Size;
		buffer = buffer.Slice(0, readBytes);
		uint id = BinaryHelper.ReadUInt32(buffer.Slice(Layout.IdOffset, Layout.IdSize));
		if (id > _lastId)
		{
			_lastId = id;
		}
		if (deleted)
		{
			data = null;
			return false;
		}
		data = type.Creator(buffer);
		data.Id = id;
		data._state = BinaryHelper.ReadUInt32(buffer.Slice(Layout.ParentIdOffset, Layout.ParentIdSize));
		Span<byte> s_actualHash = stackalloc byte[SHA256.HashSize];
		SHA256.ComputeHash(buffer.Slice(HashStart), s_actualHash);
		if(!MemoryHelper.Compare(data.Hash.Span, s_actualHash))
		{
			throw new DataBaseWrongHashException();
		}
		return true;
	}

	internal static void OrganizeHierarchy(DataSet dataSet, IList<Data> root)
	{
		foreach (var data in dataSet)
		{
			data.EnsureNotInited();
			uint parentId = data._state;
			if (parentId != NullId)
			{
				FolderData parent = (FolderData?)dataSet[parentId]
					?? throw new InvalidOperationException("Parent mismatch.");
				data._parent = parent;
				parent.Add(data);
			}
			else //no parent
			{
				root.Add(data);
			}
			data.FinishInit();
		}
	}

	public void FinishInit()
	{
		EnsureNotInited();
		if (Id == NullId)
		{
			Id = GetId();
			TimeStamp = DateTime.Now;
		}
		_state = uint.MaxValue;
	}

	internal void Flush(Span<byte> raw)
	{
		LastEdit = DateTime.Now;
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

	protected abstract void FlushCore(Span<byte> raw);

	protected static T GetSensitive<T>(ref T? field)
	{
		if (field is null)
		{
			throw new InvalidOperationException("Sensitive data is not loaded.");
		}
		return field;
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
		if (!Equals(field, newValue))
		{
			field = newValue;
			++Changes;
		}
	}
	/// <summary>
	/// Ensures no changes in object.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	protected void EnsureNoChanges()
	{
		if (Changes != 0)
		{
			throw new InvalidOperationException("Object has changes.");
		}
	}
	protected void EnsureInited()
	{
		if (_state != uint.MaxValue)
		{
			throw new InvalidOperationException("Object is not inited.");
		}
	}
	protected void EnsureNotInited()
	{
		if (_state == uint.MaxValue)
		{
			throw new InvalidOperationException("Object is inited.");
		}
	}
}
