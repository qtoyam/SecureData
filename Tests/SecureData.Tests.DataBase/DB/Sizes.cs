using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.Hash;

namespace SecureData.Tests.DataBase.DB
{
	internal static class Sizes
	{
		public const int HashSize = 32;
		public const int HashOffset = 0;

		public const int VersionSize = 16;
		public const int VersionOffset = HashOffset + HashSize;

		public const int SaltSize = 16;
		public const int SaltOffset = VersionSize + VersionOffset;

		public const int LoginSize = 256;
		public const int LoginOffset = SaltSize + SaltOffset;

		public const int Size = LoginOffset + LoginSize;
		public const int RNGOffset = Size;
		public const int RNGSize = 11968;
		public const int HashStart = HashSize;
		public const int SelfEncryptStart = RNGOffset;

		public const int DBSize = Size + RNGSize;
	}
}
