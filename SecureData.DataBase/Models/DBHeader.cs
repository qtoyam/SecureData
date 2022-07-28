using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase.Models
{
	//TODO: version != currentVersion => do something
	internal class DBHeader
	{
		public static class Layout
		{
			public const int HashSize = 32;
			public const int HashOffset = 0;

			public const int VersionSize = 16;
			public const int VersionOffset = HashOffset + HashSize;

			public const int SaltSize = 16;
			public const int SaltOffset = VersionSize + VersionOffset;

			public const int LoginSize = 64;
			public const int LoginOffset = SaltSize + SaltOffset;

			public const int RNGOffset = LoginSize + LoginOffset;
			public const int RNGSize = 16;
		}
		public const int Size = Layout.LoginOffset + Layout.LoginSize;
		public const int HashStart = Layout.VersionOffset;

		public bool IsInited => _version != 0;

		public Memory<byte> RawMemory { get; }

		private uint _version = 0;
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

		public void Update()
		{
			Span<byte> raw = RawMemory.Span;
			_version = BinaryHelper.ReadUInt32(raw.Slice(Layout.VersionOffset, Layout.VersionSize));
			_login = BinaryHelper.ReadString(raw.Slice(Layout.LoginOffset, Layout.LoginSize));
			Changes = 0;
		}

		public void Flush()
		{
			if (Changes == 0)
			{
				return;
			}
			Span<byte> raw = RawMemory.Span;
			BinaryHelper.Write(raw.Slice(Layout.VersionOffset, Layout.VersionSize), _version);
			BinaryHelper.WriteStringWithRNG(raw.Slice(Layout.LoginOffset, Layout.LoginSize), _login);
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
