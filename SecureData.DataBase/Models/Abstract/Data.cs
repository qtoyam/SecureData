using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Reflection;

using SecureData.Cryptography.Hash;
using SecureData.DataBase.Helpers;
using SecureData.DataBase.Services;

//TODO:0 mb create AesPool and clean it when needed
//TODO:1 lazy load string props
namespace SecureData.DataBase.Models.Abstract
{
	public abstract class Data
	{
		public const uint NullId = 0U;
		public const uint DeletedFlag = 1U << 31;
		public const int MinSizeToFindDataType = Layout.DataTypeSize;
		public static readonly int MaxSize;
		public static readonly int DividableBy = Cipher.BlockSize;

		private static uint _lastId = NullId;
		private static uint GetId() => Interlocked.Increment(ref _lastId);
		private readonly static (uint DataType, int Size, Func<Memory<byte>, Data> Creator)[] Types;

		static Data()
		{
			int max = 1;
			int value_SizeConst;
			var type_Data = typeof(Data);
			List<(uint DataType, int Size, Func<Memory<byte>, Data> Creator)> types = new();
			ParameterExpression param_Raw = Expression.Parameter(typeof(Memory<byte>));
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
					uint value_DataTypeConst = (uint)
						field_DataTypeConst.GetValue(null)!;
					if (value_DataTypeConst == Data.DataTypeConst)
					{
						throw new NotImplementedException($"Type \"{t.FullName}\", const field {nameof(DataTypeConst)} value equals to {nameof(Data)} value.");
					}
					//size
					var field_SizeConst = t.GetField(nameof(SizeConst), BindingFlags.NonPublic | BindingFlags.Static)
						?? throw new NotImplementedException($"Type \"{t.FullName}\", not implemented const field {nameof(SizeConst)}.");
					value_SizeConst = (int)
						field_SizeConst
						.GetValue(null)!;
					if (value_SizeConst == Data.SizeConst)
					{
						throw new NotImplementedException($"Type \"{t.FullName}\", const field {nameof(SizeConst)} value equals to {nameof(Data)} value.");
					}
					if ((value_SizeConst % DividableBy) != 0)
					{
						throw new NotImplementedException($"Type \"{t.FullName}\", const field {nameof(SizeConst)} value not dividable by {nameof(DividableBy)}.");
					}
					if (value_SizeConst > max)
					{
						max = value_SizeConst;
					}

					var ctor = t.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance,
						new Type[] { typeof(Memory<byte>) })
						?? throw new NotImplementedException($"Type \"{t.FullName}\", not implemented protected(!) constructor.");
					var creator = Expression.Lambda<Func<Memory<byte>, Data>>(
						   Expression.New(ctor, param_Raw), param_Raw
						   ).Compile();
					types.Add(new(value_DataTypeConst, value_SizeConst, creator));
				}
			}
			MaxSize = max;
			Types = types.ToArray();
			for (int i = 0; i < Types.Length - 1; i++)
			{
				uint currentDataType = Types[i].DataType;
				for (int j = i + 1; j < Types.Length; j++)
				{
					uint comparedDataType = Types[j].DataType;
					if (currentDataType == comparedDataType)
					{
						throw new InvalidOperationException($"Multiple data items have same data type identifier ({currentDataType})");
					}
				}
			}
		}

		/// <summary>
		/// Count of changes in object since last update/flush.
		/// </summary>
		public int Changes { get; private set; }

		private static class Layout
		{
			public const int HashOffset = 0;
			public const int HashSize = 32;

			public const int DataTypeOffset = HashOffset + HashSize;
			public const int DataTypeSize = sizeof(uint);

			public const int IdOffset = DataTypeOffset + DataTypeSize;
			public const int IdSize = sizeof(uint);

			public const int ParentIdOffset = IdOffset + IdSize;
			public const int ParentIdSize = sizeof(uint);

			public const int IsEncryptedOffset = ParentIdOffset + ParentIdSize;
			public const int IsEncryptedSize = 4; //3 byte padding

			public const int TimeStampOffset = IsEncryptedOffset + IsEncryptedSize;
			public const int TimeStampSize = sizeof(long); //DateTime

			public const int LastEditOffset = TimeStampOffset + TimeStampSize;
			public const int LastEditSize = sizeof(long); //DateTime

			public const int SaltOffset = LastEditOffset + LastEditSize;
			public const int SaltSize = 16;
		}
		protected const int SizeConst = Layout.SaltOffset + Layout.SaltSize;
		protected const uint DataTypeConst = DeletedFlag;

		#region DB
		#region Private write-access
		private readonly Memory<byte> _hashInternal;
		private FolderData? _parent;
		private DateTime _timeStamp;
		private DateTime _lastEdit;
		private readonly Memory<byte> _saltInternal;
		#endregion
		public ReadOnlyMemory<byte> Hash => _hashInternal;
		public abstract uint DataType { get; }
		public uint Id { get; private set; } = NullId;
		public FolderData? Parent
		{
			get => _parent;
			internal set => Set(ref _parent, value);
		}
		public bool IsEncrypted { get; private set; }
		public DateTime TimeStamp
		{
			get => Get(ref _timeStamp);
			private set => _timeStamp = value;
		} //const
		public DateTime LastEdit
		{
			get => Get(ref _lastEdit);
			private set => Set(ref _lastEdit, value);
		}
		public ReadOnlyMemory<byte> Salt => _saltInternal;
		#endregion

		/// Do ONLY slice from <paramref name="raw"/>.
		/// Do NOT store it or modify.
		protected Data(Memory<byte> raw, bool isNew)
		{
			Debug.Assert(raw.Length == Size);
			Debug.Assert(ObjectCipherStart <= Size);
			_rawMemory = raw;
			_hashInternal = _rawMemory.Slice(Layout.HashOffset, Layout.HashSize);
			_saltInternal = _rawMemory.Slice(Layout.SaltOffset, Layout.SaltSize);
			if (isNew)
			{
				MemoryHelper.RNG(_saltInternal.Span);
			}
		}

		private Cipher? _localCipher;
		private readonly Memory<byte> _rawMemory;

		/// <summary>
		/// Raw memory that can NOT be ciphered locally.
		/// </summary>
		private ReadOnlySpan<byte> RawPublic => _rawMemory.Span.Slice(0, ObjectCipherStart);
		/// <summary>
		/// Raw memory that can be ciphered locally.
		/// </summary>
		private Span<byte> RawSensitive => _rawMemory.Span.Slice(ObjectCipherStart);
		/// <summary>
		/// Raw memory that can be ciphered by parent.
		/// </summary>
		private Span<byte> RawParentCipherable => _rawMemory.Span.Slice(ParentCipherStart);
		/// <summary>
		/// Raw memory that can be hashed.
		/// </summary>
		private ReadOnlySpan<byte> RawHashable => _rawMemory.Span.Slice(HashStart);

		/// <summary>
		/// Point from object hashing starts.
		/// </summary>
		protected const int HashStart = Layout.DataTypeOffset;
		/// <summary>
		/// Point from parent encryption starts.
		/// </summary>
		protected const int ParentCipherStart = Layout.TimeStampOffset;
		/// <summary>
		/// Total parent cipher layers.
		/// </summary>
		protected int ParentLayers { get; private set; } = 0;
		/// <summary>
		/// Total locked parent cipher layers.
		/// </summary>
		protected int ParentLockedLayers { get; private set; } = 0;

		internal void ChangeParentLayers(int diff)
		{
			ParentLayers += diff;
			if (ParentLayers < 0)
			{
				throw new InvalidOperationException("Parent layers can not be less than zero.");
			}
		}

		/// <summary>
		/// Total size.
		/// </summary>
		public abstract int Size { get; }
		/// <summary>
		/// Point from local cipher starts.
		/// Can be set to <see cref="Size"/> if no local cipher needed.
		/// </summary>
		protected abstract int ObjectCipherStart { get; }

		/// <summary>
		/// Returns <see langword="false"/> if locked by parent or/and locally, otherwise <see langword="true"/>.
		/// </summary>
		public bool IsVisible
		{
			get
			{
				if (IsLockedByParent)
				{
					return false;
				}
				else if (!IsEncrypted)
				{
					return true;
				}
				else
				{
					return _localCipher is not null; //if LocalCipher exists it means item is encrypted and unlocked
				}
			}
		}

		/// <summary>
		/// Returns <see langword="true"/> if object is locked by parent, otherwise <see langword="false"/>.
		/// </summary>
		public bool IsLockedByParent => ParentLockedLayers != 0;

		/// <summary>
		/// Copy object to <paramref name="s_buffer"/> and locks it there.
		/// Does NOT lock object locally.
		/// </summary>
		/// <param name="s_buffer"></param>
		public void LockMeTemp(Span<byte> s_buffer)
		{
			Span<byte> s_item = s_buffer.Slice(0, Size);
			EnsureNoChanges();
			EnsureParentUnlocked();
			if (IsEncrypted)
			{
				EnsureUnlocked();
				_localCipher.Reset();
				_localCipher.Transform(RawSensitive, s_item.Slice(ObjectCipherStart));
				MemoryHelper.Copy(RawPublic, s_item); //non-sensitive data
			}
			else //if !IsEncrypted
			{
				MemoryHelper.Copy(_rawMemory.Span, s_item); //just copy
			}
			FolderData? currentParent = _parent;
			Span<byte> s_parentLockable = s_item.Slice(ParentCipherStart);
			while (currentParent is not null)
			{
				Cipher? parentCipher = currentParent._localCipher;
				if (parentCipher is not null)
				{
					parentCipher.Wide();
					parentCipher.Reset(Id);
					parentCipher.Transform(s_parentLockable);
					parentCipher.Local();
				}
				currentParent = currentParent.Parent;
			}
		}

		/// <summary>
		/// Updates non-sensitive data from raw memory into object.
		/// </summary>
		protected virtual void UpdateData(ReadOnlySpan<byte> raw)
		{
			//-----------------------------
			//-----not parent-lockable-----
			//hash
			//datatype
			//id
			//parent
			//isencrypted
			//-----------------------------
			TimeStamp = BinaryHelper.ReadDateTime(raw.Slice(Layout.TimeStampOffset, Layout.TimeStampSize));
			_lastEdit = BinaryHelper.ReadDateTime(raw.Slice(Layout.LastEditOffset, Layout.LastEditSize));
			//salt is related to raw memory
		}
		/// <summary>
		/// Updates sensitive data from raw memory into object.
		/// </summary>
		/// <param name="raw">
		/// Starts at <see cref="ObjectCipherStart"/> offset.
		/// </param>
		protected virtual void UpdateSensitiveData(ReadOnlySpan<byte> raw) { }

		/// <summary>
		/// Flushes all data from object into raw memory.
		/// </summary>
		protected virtual void FlushAll(Span<byte> raw)
		{
			//use back-fields instead of props to skip parent lock check
			//also no need to flush Hash, DataType, Id, Parent, IsEncrypted cauze they are not locked by parent
			//and must be flushed in InitNew
			BinaryHelper.Write(raw.Slice(Layout.TimeStampOffset, Layout.TimeStampSize), TimeStamp);
			BinaryHelper.Write(raw.Slice(Layout.LastEditOffset, Layout.LastEditSize), _lastEdit);
			//salt is already in raw
		}

		/// <summary>
		/// Locks external stuff.
		/// </summary>
		protected virtual void LockExternal(Cipher cipher) { }
		/// <summary>
		/// Unlocks external stuff.
		/// </summary>
		protected virtual void UnlockExternal(Cipher cipher) { }

		/// <summary>
		/// Clears non-sensitive parent-lockable data from object.
		/// </summary>
		protected virtual void ClearData()
		{
			TimeStamp = default;
			_lastEdit = default;
		}
		/// <summary>
		/// Clears sensitive data from object.
		/// </summary>
		protected virtual void ClearSensitiveData() { }

		/// <summary>
		/// Locks external stuff after locked by parent.
		/// </summary>
		protected virtual void LockLayerExternal(Cipher cipher) { }
		/// <summary>
		/// Unlocks external stuff after unlocked by parent.
		/// </summary>
		protected virtual void UnlockLayerExternal(Cipher cipher) { }

		/// <summary>
		/// Initializes new object. Flushes raw data to memory from object.
		/// </summary>
		internal void InitNew()
		{
			if (Id != NullId)
			{
				throw new InvalidOperationException("Object already inited id.");
			}
			//LastEdit = DateTime.Now; //ensure visible
			EnsureVisible();
			Id = GetId();
			Span<byte> raw = _rawMemory.Span;
			//------non parent-lockable------
			BinaryHelper.Write(raw.Slice(Layout.DataTypeOffset, Layout.DataTypeSize), DataType);
			BinaryHelper.Write(raw.Slice(Layout.IdOffset, Layout.IdSize), Id);
			BinaryHelper.Write(raw.Slice(Layout.ParentIdOffset, Layout.ParentIdSize), _parent?.Id ?? NullId);
			BinaryHelper.Write(raw.Slice(Layout.IsEncryptedOffset, Layout.IsEncryptedSize), IsEncrypted);
			//-------------------------------
			TimeStamp = DateTime.Now;
			Changes++; //for timestamp
			Flush();
		}
		/// <summary>
		/// Updates non-readonly data from raw memory to object.
		/// </summary>
		private void Update()
		{
			EnsureParentUnlocked();
			UpdateData(RawPublic);
			if (IsVisible)
			{
				UpdateSensitiveData(RawSensitive);
			}
			Changes = 0;
		}
		/// <summary>
		/// Flushes non-readonly data from object to raw memory and recomputes hash.
		/// </summary>
		private void Flush()
		{
			if (Changes == 0)
			{
				return;
			}
			LastEdit = DateTime.Now; //also ensure visible
			FlushAll(_rawMemory.Span);
			SHA256.ComputeHash(RawHashable, _hashInternal.Span);
			Changes = 0;
		}

		/// <summary>
		/// Locks object by parent and clear data if needed.
		/// </summary>
		/// <exception cref="InvalidProgramException">
		/// All layers locked.
		/// </exception>
		internal void LockLayer(Cipher cipher)
		{
			if (ParentLockedLayers == ParentLayers)
			{
				throw new InvalidProgramException("All layers locked.");
			}
			if (!IsLockedByParent) //was not locked by parent before, need to clear data from object
			{
				EnsureNoChanges();
				ClearSensitiveData();
				ClearData();
			}
			cipher.Reset(Id);
			cipher.Transform(RawParentCipherable);
			LockLayerExternal(cipher);
			++ParentLockedLayers;
		}
		/// <summary>
		/// Unlocks object from parent and update data if needed.
		/// </summary>
		/// <exception cref="InvalidOperationException">
		/// All layers unlocked.
		/// </exception>
		internal void UnlockLayer(Cipher cipher)
		{
			if (!IsLockedByParent)
			{
				throw new InvalidOperationException("No locked layers above.");
			}
			cipher.Reset(Id);
			cipher.Transform(RawParentCipherable);
			UnlockLayerExternal(cipher);
			--ParentLockedLayers;
			if (!IsLockedByParent)
			{
				Update();
			}
		}

		/// <summary>
		/// Locks object and clears all sensitive data.
		/// </summary>
		private void Lock()
		{
			EnsureUnlocked();
			EnsureNoChanges();
			_localCipher.Reset();
			using (_localCipher)
			{
				if (ObjectCipherStart < Size)
				{
					ClearSensitiveData();
					_localCipher.Transform(RawSensitive);
				}
				LockExternal(_localCipher.Wide());
			}
			_localCipher = null;
		}
		/// <summary>
		/// Unlocks object and updates sensitive data.
		/// </summary>
		public bool TryUnlock(ReadOnlySpan<byte> key)
		{
			Debug.Assert(ObjectCipherStart < Size);
			EnsureParentUnlocked();
			EnsureLocked();
			//transform
			_localCipher = new Cipher(key, Salt.Span, true);
			_localCipher.Transform(RawSensitive);
			//verify
			Span<byte> actual_Hash = stackalloc byte[SHA256.HashSize];
			SHA256.ComputeHash(RawHashable, actual_Hash);
			if (!MemoryHelper.Compare(_hashInternal.Span, actual_Hash))
			{
				//restore data
				using (_localCipher)
				{
					_localCipher.Reset();
					_localCipher.Transform(RawSensitive);
				}
				_localCipher = null;
				return false;
			}
			UpdateSensitiveData(RawSensitive);
			UnlockExternal(_localCipher.Wide());
			_localCipher.Local();
			return true;
		}

		public void MakeEncrypted(ReadOnlySpan<byte> key)
		{
			if (IsEncrypted)
			{
				throw new InvalidOperationException("Object already encrypted.");
			}
			EnsureVisible();
			_localCipher = new Cipher(key, Salt.Span, true);
			MakeEncryptedExternal(_localCipher.Wide());
			_localCipher.Local();
			IsEncrypted = true;
		}

		public void MakeUnencrypred()
		{
			EnsureUnlocked();
			using (_localCipher)
			{
				MakeUnencryptedExternal(_localCipher.Wide());
			}
			_localCipher = null;
			IsEncrypted = false;
		}

		protected virtual void MakeEncryptedExternal(Cipher cipher) { }
		protected virtual void MakeUnencryptedExternal(Cipher cipher) { }

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
			Debug.Assert(buffer.Length >= MinSizeToFindDataType);
			uint dataType = BinaryHelper.ReadUInt32(buffer.Slice(Layout.DataTypeOffset, Layout.DataTypeSize));
			bool deleted = (dataType & DeletedFlag) == DeletedFlag;
			dataType &= ~DeletedFlag; //remove ONLY deleted flag
			var type = Types.Single(x => x.DataType == dataType);
			if (type.Size > buffer.Length)
			{
				data = null;
				readBytes = 0;
				return false;
			}
			uint id = BinaryHelper.ReadUInt32(buffer.Slice(Layout.IdOffset, Layout.IdSize));
			if (id > _lastId)
			{
				_lastId = id;
			}
			readBytes = type.Size;
			if (deleted)
			{
				data = null;
				return false;
			}
			Memory<byte> raw = new byte[type.Size];
			buffer.Slice(0, type.Size).CopyTo(raw.Span);
			data = type.Creator(raw);
			//init non parent-lockable memory
			data.Id = id;
			data.IsEncrypted = BinaryHelper.ReadBool(buffer.Slice(Layout.IsEncryptedOffset, Layout.IsEncryptedSize));
			//parent id must be set in OrganizeHierarchy
			return true;
		}

		//TODO:4 custom dictionary class
		internal static void OrganizeHierarchy(IReadOnlyDictionary<uint, Data> hiearchy, IList<Data> root)
		{
			foreach (var data in hiearchy.Values)
			{
				uint parentId =
					BinaryHelper.ReadUInt32(data._rawMemory.Span.Slice(Layout.ParentIdOffset, Layout.ParentIdSize));
				if (parentId != NullId)
				{

					FolderData parent = (FolderData?)hiearchy[parentId]
						?? throw new InvalidOperationException("Parent mismatch.");
					data._parent = parent;
					parent.AddOnInit(data);
				}
				else //no parent
				{
					root.Add(data);
				}
			}
			foreach (var data in root)
			{
				InitLocksRecursively(data);
			}
			//TODO:0 mb freeze object after init (folder = addoninit freezed, item = timestamp and id freezed)
		}
		private static void InitLocksRecursively(Data data)
		{
			FolderData? parent = data.Parent;
			if (parent is not null)
			{
				data.ParentLayers = parent.ParentLayers;
				data.ParentLockedLayers = parent.ParentLockedLayers;
				if (parent.IsEncrypted)
				{
					++data.ParentLayers;
					++data.ParentLockedLayers;
				}
			}
			else
			{
				data.ParentLayers = 0;
				data.ParentLockedLayers = 0;
			}
			if (!data.IsLockedByParent)
			{
				data.Update();
			}
			if (data is FolderData folder)
			{
				foreach (var child in folder.Childs.Values)
				{
					InitLocksRecursively(child);
				}
			}
		}

		/// <summary>
		/// Use this to get back-field of any non-sensitive raw memory related property.
		/// Ensures object is not locked by parent.
		/// </summary>
		/// <typeparam name="T">
		/// Field type.
		/// </typeparam>
		/// <param name="field">
		/// Field reference.
		/// </param>
		/// <returns>
		/// Field value.
		/// </returns>
		protected T Get<T>(ref T field)
		{
			EnsureParentUnlocked();
			return field;
		}
		/// <summary>
		/// Use this to get back-field of any sensitive raw memory related property.
		/// Ensures object is not locked any way.
		/// </summary>
		/// <typeparam name="T">
		/// Field type.
		/// </typeparam>
		/// <param name="field">
		/// Field value.
		/// </param>
		/// <returns></returns>
		protected T GetSensitive<T>(ref T field)
		{
			EnsureVisible();
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
			EnsureVisible();
			field = newValue;
			++Changes;
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

		/// <summary>
		/// Ensures there is no parent lock.
		/// </summary>
		/// <exception cref="InvalidOperationException"></exception>
		protected void EnsureParentUnlocked()
		{
			if (IsLockedByParent)
			{
				throw new InvalidOperationException("Object is locked by parent.");
			}
		}
		/// <summary>
		/// Ensures object is not locked by parent and (not encrypted or not locked).
		/// </summary>
		/// <exception cref="InvalidOperationException"></exception>
		protected void EnsureVisible()
		{
			if (!IsVisible)
			{
				throw new InvalidOperationException("Object is not visible.");
			}
		}

		/// <summary>
		/// Ensures that object is encrypted and unlocked.
		/// </summary>
		/// <exception cref="InvalidOperationException"></exception>
		[MemberNotNull(nameof(_localCipher))]
		private void EnsureUnlocked()
		{
			//will return only if LocalAes != null => IsEncrypted == true
			if (_localCipher == null)
			{
				throw new InvalidOperationException("Object is locked or not encrypted.");
			}
		}
		/// <summary>
		/// Ensures that object is encrypted and locked.
		/// </summary>
		/// <exception cref="InvalidOperationException"></exception>
		private void EnsureLocked()
		{
			if (!IsEncrypted || _localCipher != null)
			{
				throw new InvalidOperationException("Object is unlocked or not encrypted.");
			}
		}

		internal void Clear()
		{
			MemoryHelper.ZeroOut(_rawMemory.Span);
		}
	}
}
