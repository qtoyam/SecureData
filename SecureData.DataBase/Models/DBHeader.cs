﻿namespace SecureData.DataBase.Models
{
	public class DBHeader
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

			public const int RealSize = LoginOffset + LoginSize;

			public const int RNGOffset = RealSize;
			public const int RNGSize = 11968;

			public const int HashingStart = VersionOffset; //hash from version
			public const int EncryptionStart = RNGOffset; //encrypt from RNG

			public const int DBSize = RealSize + RNGSize;
		}
		public ReadOnlyMemory<byte> Hash => HashCore;
		internal Memory<byte> HashCore { get; }
		public uint Version { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		public string Login { get; }

		public DBHeader(Memory<byte> hash, uint version, ReadOnlyMemory<byte> salt, string login)
		{
			HashCore = hash;
			Version = version;
			Salt = salt;
			Login = login;
		}
	}
}
