using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

using SecureData.Cryptography.SymmetricEncryption;

//mb create project realisation of aes called "encryption" with locked to public counter
namespace SecureData.DataBase.Models.Abstract
{
	public abstract class Data
	{
		private static class Layout
		{
			public const int HashOffset = 0;
			public const int HashSize = 32;

			public const int DataTypeOffset = HashOffset + HashSize;
			public const int DataTypeSize = sizeof(DataType);

			public const int IdOffset = DataTypeOffset + DataTypeSize;
			public const int IdSize = sizeof(uint);

			public const int ParentIdOffset = IdOffset + IdSize;
			public const int ParentIdSize = sizeof(uint);

			public const int TimeStampOffset = ParentIdOffset + ParentIdSize;
			public const int TimeStampSize = sizeof(long);

			public const int IsEncryptedOffset = TimeStampOffset + TimeStampSize;
			public const int IsEncryptedSize = 2; //1 byte padding

			public const int SaltOffset = IsEncryptedOffset + IsEncryptedSize;
			public const int SaltSize = 16;
		}

		/// <summary>
		/// Current item cipher.
		/// </summary>
		private Aes? _localAes;
		private readonly Memory<byte> _rawMemory;

		/// <summary>
		/// <see cref="_rawMemory"/> until <see cref="SelfEncryptStart"/>.
		/// </summary>
		private Span<byte> RawPublic => _rawMemory.Span.Slice(0, SelfEncryptStart);
		/// <summary>
		/// <see cref="_rawMemory"/> from <see cref="SelfEncryptStart"/>.
		/// </summary>
		private Span<byte> RawSensitive => _rawMemory.Span.Slice(SelfEncryptStart);
		/// <summary>
		/// <see cref="_rawMemory"/> from <see cref="LayerEncryptStart"/>.
		/// </summary>
		private Span<byte> RawParentEncryptable => _rawMemory.Span.Slice(LayerEncryptStart);

		/// <summary>
		/// Point from object hashing starts.
		/// </summary>
		protected const int HashStart = Layout.DataTypeOffset;
		/// <summary>
		/// Point from parent encryption starts.
		/// </summary>
		protected const int LayerEncryptStart = Layout.TimeStampOffset;
		/// <summary>
		/// Total parent encrypt layers.
		/// </summary>
		protected int LayersAbove { get; private set; }
		/// <summary>
		/// Locked parent encrypt layers.
		/// </summary>
		protected int LockedLayers { get; private set; }
		/// <summary>
		/// Object in bytes.
		/// </summary>
		protected ReadOnlyMemory<byte> RawMemory => _rawMemory;

		/// <summary>
		/// Total size.
		/// </summary>
		public virtual int Size => Layout.SaltOffset + Layout.SaltSize;
		/// <summary>
		/// Point from object encryption starts.
		/// </summary>
		public abstract int SelfEncryptStart { get; }
		#region DB
		#region Internal write-access memory regions.
		internal Memory<byte> HashInternal { get; }
		internal Memory<byte> SaltInternal { get; }
		#endregion
		public Memory<byte> Hash => HashInternal;
		public DataType DataType { get; private set; }
		public uint Id { get; private set; }
		public uint ParentId { get; private set; }
		public DateTime TimeStamp { get; private set; }
		public bool IsEncrypted { get; private set; }
		public ReadOnlyMemory<byte> Salt => SaltInternal;
		#endregion

		/// <summary>
		/// Returns <see langword="true"/> if object is locked locally, otherwise <see langword="false"/>.
		/// </summary>
		[MemberNotNullWhen(false, nameof(_localAes))]
		public bool IsLocked => _localAes == null;
		/// <summary>
		/// Returns <see langword="true"/> if object is locked by parent, otherwise <see langword="false"/>.
		/// </summary>
		public bool IsLockedByParent => LockedLayers != 0;

		/// <summary>
		/// Do ONLY slice from <see cref="RawMemory"/>.
		/// Do NOT initalize any other data here.
		/// </summary>
		protected Data()
		{
			Debug.Assert(Aes.IsValidSize(Size));
			_rawMemory = new byte[Size];
			HashInternal = _rawMemory.Slice(Layout.HashOffset, Layout.HashSize);
			SaltInternal = _rawMemory.Slice(Layout.SaltOffset, Layout.SaltSize);
		}

		/// <summary>
		/// Updates non-sensitive data.
		/// </summary>
		/// <param name="rawMemory_ptr">
		/// <see cref="RawMemory"/> pointer at zero offset.
		/// Not locked by parent.
		/// Do NOT modify it.
		/// </param>
		protected virtual unsafe void UpdateData(byte* rawMemory_ptr)
		{
			DataType = (DataType)BinaryHelper.ReadUInt32(rawMemory_ptr, Layout.DataTypeOffset);
			Id = BinaryHelper.ReadUInt32(rawMemory_ptr, Layout.IdOffset);
			ParentId = BinaryHelper.ReadUInt32(rawMemory_ptr, Layout.ParentIdOffset);
			TimeStamp = BinaryHelper.ReadDateTime(rawMemory_ptr, Layout.TimeStampOffset);
			IsEncrypted = BinaryHelper.ReadBool(rawMemory_ptr, Layout.IsEncryptedOffset);
		}
		/// <summary>
		/// Updates sensitive data.
		/// </summary>
		/// <param name="rawMemory_ptr">
		/// <see cref="RawMemory"/> pointer at <see cref="SelfEncryptStart"/> offset.
		/// Not locked locally.
		/// Do NOT modify it.
		/// </param>
		protected virtual unsafe void UpdateSensitiveData(byte* rawMemory_ptr) { }

		/// <summary>
		/// Locks external stuff after self locked.
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/> to <see cref="Size"/>.
		/// </param>
		protected virtual void LockExternal(Aes aes) { }
		/// <summary>
		/// Unlocks external stuff after self unlocked.
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/> to <see cref="Size"/>.
		/// </param>
		protected virtual void UnlockExternal(Aes aes) { }

		/// <summary>
		/// Clears non-sensitive data after.
		/// </summary>
		protected virtual void ClearData()
		{
			TimeStamp = default;
			IsEncrypted = default;
		}
		/// <summary>
		/// Clears sensitive data after <see cref="SelfEncryptStart"/>.
		/// </summary>
		protected virtual void ClearSensitiveData() { }

		/// <summary>
		/// Locks external stuff after parent layer locked.
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/>.
		/// </param>
		protected virtual void LockLayerExternal(Aes aes) { }
		/// <summary>
		/// Unlocks external stuff after parent layer unlocked.
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/>.
		/// </param>
		protected virtual void UnlockLayerExternal(Aes aes) { }

		/// <summary>
		/// Updates data from <see cref="RawMemory"/>.
		/// </summary>
		/// <exception cref="InvalidOperationException">
		/// Object is locked by parent.
		/// </exception>
		private void Update()
		{
			if (IsLockedByParent)
			{
				throw new InvalidOperationException("Object is locked by parent.");
			}
			unsafe
			{
				fixed(byte* rawPublic_ptr = RawPublic)
				{
					UpdateData(rawPublic_ptr);
				}
				if(!IsLocked)
				{
					fixed(byte* rawSensitive_ptr = RawSensitive)
					{
						UpdateSensitiveData(rawSensitive_ptr);
					}
				}
			}
		}

		/// <summary>
		/// Locks object by layer recursively (localy).
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/>.
		/// </param>
		/// <exception cref="InvalidProgramException">
		/// All layers locked.
		/// </exception>
		internal void LockLayer(Aes aes)
		{
			if (LockedLayers == LayersAbove)
			{
				throw new InvalidProgramException("All layers locked.");
			}
			aes.Transform(RawParentEncryptable);
			if (!IsLockedByParent) //if was not locked previously
			{
				ClearSensitiveData();
				ClearData();
			}
			LockLayerExternal(aes);
			++LockedLayers;
		}
		/// <summary>
		/// Unlocks object from encrypt layer recursively (localy).
		/// </summary>
		/// <param name="aes">
		/// Aes with moved <see cref="Aes.Counter"/>
		/// </param>
		/// <exception cref="InvalidOperationException">
		/// All layers unlocked.
		/// </exception>
		internal void UnlockLayer(Aes aes)
		{
			if (LockedLayers == 0)
			{
				throw new InvalidOperationException("No locked layers above.");
			}
			aes.Transform(RawParentEncryptable);
			UnlockLayerExternal(aes);
			--LockedLayers;
			if (!IsLockedByParent)
			{
				Update();
			}
		}

		/// <summary>
		/// Locks object and clears all sensitive data.
		/// </summary>
		/// <exception cref="InvalidOperationException">
		/// Already locked.
		/// </exception>
		internal void Lock()
		{
			Debug.Assert(!IsLockedByParent);
			if (IsLocked)
			{
				throw new InvalidOperationException("Object is locked already.");
			}
			_localAes.Counter = 0;
			using (_localAes)
			{
				if (SelfEncryptStart < Size)
				{
					_localAes.Transform(RawSensitive);
					ClearSensitiveData();
				}
				LockExternal(_localAes);
			}
			_localAes = null;
		}
		/// <summary>
		/// Unlocks object and updates sensitive data.
		/// </summary>
		/// <param name="key"></param>
		/// <exception cref="InvalidOperationException">
		/// Already unlocked.
		/// </exception>
		internal void Unlock(ReadOnlySpan<byte> key)
		{
			Debug.Assert(!IsLockedByParent);
			if (!IsLocked)
			{
				throw new InvalidOperationException("Object is unlocked already.");
			}
			_localAes = new(key, Salt.Span)
			{
				Counter = 0
			};
			if (SelfEncryptStart < Size)
			{
				Span<byte> s_lockable = RawSensitive;
				_localAes.Transform(s_lockable);
				unsafe
				{
					fixed (byte* rawMemory_ptr = s_lockable)
					{
						UpdateSensitiveData(rawMemory_ptr);
					}
				}
			}
			UnlockExternal(_localAes);
		}

		public bool IsDeleted() => (DataType & DataType.Deleted) == DataType.Deleted;
		/// <summary>
		/// Creates <see cref="Data"/> type with initialized data that is always visible.
		/// </summary>
		/// <param name="buffer"></param>
		/// <returns></returns>
		internal static Data Create(ReadOnlySpan<byte> buffer)
		{
			DataType type = (DataType)BinaryHelper.ReadUInt32(buffer);
			//TODO: creation of Data!!!
			return null!;
		}

		internal static void OrganizeHierarchy(IDictionary<uint, Data> items)
		{
			//TODO: organize hierarchy
		}
	}
}
