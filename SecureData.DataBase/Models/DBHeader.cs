using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Models
{
	//TODO: version != currentVersion => do something
	public class DBHeader
	{
		public class Layout : LayoutBase
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

			public const int HashingStart = HashSize;
			public const int EncryptionStart = RNGOffset; //encrypt from RNG

			public new const int DBSize = Size + RNGSize;
		}

		private Raw _raw = new();

		public uint Version => _raw.Version;

		//TODO: cache login somehow
		public unsafe string Login
		{
			get
			{
				fixed(byte* rawLogin_ptr = _raw.Login)
				{
					return StringHelper.GetStringFromNullTerminatedBytes(rawLogin_ptr);					
				}
			}
		}

		internal void Init(Span<byte> s_dbHeader, uint version, ReadOnlySpan<byte> salt, string login)
		{
			_raw.Version = version;
			salt.CopyTo(GetSalt(s_dbHeader));
			StringHelper.WriteWithRNG(GetLogin(s_dbHeader), login);
		}


		internal Span<byte> GetRaw() => MemoryHelper.StructToSpan(in _raw);
		internal static Span<byte> GetSalt(Span<byte> raw) => raw.Slice(Layout.SaltOffset, Layout.SaltSize);
		internal static Span<byte> GetHash(Span<byte> raw) => raw.Slice(Layout.HashOffset, Layout.HashSize);
		internal static Span<byte> GetLogin(Span<byte> raw) => raw.Slice(Layout.LoginOffset, Layout.LoginSize);



		[StructLayout(LayoutKind.Explicit, Pack = 1)]
		internal unsafe struct Raw
		{
			[FieldOffset(Layout.HashOffset)]
			public fixed byte Hash[Layout.HashSize];
			[FieldOffset(Layout.VersionOffset)]
			public UInt32 Version;
			[FieldOffset(Layout.SaltOffset)]
			public fixed byte Salt[Layout.SaltSize];
			[FieldOffset(Layout.LoginOffset)]
			public fixed byte Login[Layout.LoginSize];
		}

#if DEBUG
		public Span<byte> GetRawDebug() => GetRaw();
		public static Span<byte> GetSaltDebug(Span<byte> raw) => GetSalt(raw);
		public static Span<byte> GetHashDebug(Span<byte> raw) => GetHash(raw);
		//public static Span<byte> GetLoginDebug(Span<byte> raw) => GetLogin(raw);
#endif
	}
}
