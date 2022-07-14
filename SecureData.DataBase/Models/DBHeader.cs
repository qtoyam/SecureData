using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase.Models
{
	//TODO: version != currentVersion => do something
	internal class DBHeader : IDBData
	{
		public static class Layout
		{
			public const int HashSize = 32;
			public const int HashOffset = 0;

			public const int VersionSize = 16;
			public const int VersionOffset = HashOffset + HashSize;

			public const int SaltSize = 16;
			public const int SaltOffset = VersionSize + VersionOffset;

			public const int LoginSize = 256;
			public const int LoginOffset = SaltSize + SaltOffset;
		}
		public int Size => Layout.LoginOffset + Layout.LoginSize;
		public int RNGOffset => Size;
		public int RNGSize => 11968;
		public int HashStart => Layout.HashSize;
		public int SelfEncryptStart => RNGOffset;

		public Memory<byte> RawMemory { get; }

		private uint _version;
		private string _login = string.Empty;

		public Memory<byte> Hash { get; }
		public uint Version
		{

			get => _version;
			set
			{
				_version = value;
				Changes++;
			}
		}
		public Memory<byte> Salt { get; }
		public string Login
		{
			get => _login;
			set
			{
				_login = value;
				Changes++;
			}
		}
		public int Changes { get; private set; }


		public ReadOnlySpan<byte> GetRawHashable() => RawMemory.Slice(HashStart).Span;

		public unsafe void Update()
		{
			fixed (byte* rawMemory_ptr = RawMemory.Span)
			{
				_version = BinaryHelper.ReadUInt32(rawMemory_ptr, Layout.VersionOffset);
				_login = BinaryHelper.ReadString(rawMemory_ptr, Layout.LoginOffset);
			}
			Changes = 0;
		}

		public void Flush()
		{
			if (Changes == 0)
			{
				return;
			}
			unsafe
			{
				fixed (byte* rawMemory_ptr = RawMemory.Span)
				{
					BinaryHelper.Write(rawMemory_ptr, Layout.VersionOffset, _version);
					BinaryHelper.Write(rawMemory_ptr, Layout.LoginOffset, _login, Layout.LoginSize);
				}
			}
			Changes = 0;
		}

		public DBHeader()
		{
			RawMemory = new byte[Size];
			Hash = RawMemory.Slice(Layout.HashOffset, Layout.HashSize);
			Salt = RawMemory.Slice(Layout.SaltOffset, Layout.SaltSize);
		}
	}
}
