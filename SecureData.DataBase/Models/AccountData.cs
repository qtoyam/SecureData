using System;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Models
{
	internal sealed class AccountData : IEncryptedData
	{
		public class Layout : IEncryptedData.Layout
		{
			public const int NameOffset = IEncryptedData.Layout.Size;
			public const int NameSize = 128;

			public const int DescriptionOffset = NameOffset + NameSize;
			public const int DescriptionSize = 256;

			public const int LoginOffset = DescriptionOffset + DescriptionSize;
			public const int LoginSize = 128;

			public const int PasswordOffset = LoginOffset + LoginSize;
			public const int PasswordSize = 128;

			public new const int Size = PasswordOffset + PasswordSize; //from IData

			public const int RNGOffset = Size;
			public const int RNGSize = 10;

			public new const int DBSize = RNGOffset + RNGSize; //from LayoutBase
			public new const int EncryptionStart = LoginOffset; //from IEncryptedData
		}

		private readonly Raw _raw;
		public int CopyTo(Span<byte> buffer)
		{
			ReadOnlySpan<byte> rawBytes = MemoryHelper.StructToReadOnlySpan(in _raw);
			rawBytes.CopyTo(buffer);
			return rawBytes.Length;
		}

		public uint Id => _raw.Id;

		[StructLayout(LayoutKind.Explicit, Pack = 1)]
		internal unsafe struct Raw
		{
			[FieldOffset(Layout.HashOffset)]
			public fixed byte Hash[Layout.HashSize];
			[FieldOffset(Layout.DataTypeOffset)]
			public DataType DataType;
			[FieldOffset(Layout.IdOffset)]
			public UInt32 Id;
			[FieldOffset(Layout.ParentIdOffset)]
			public UInt32 ParentId;
			[FieldOffset(Layout.TimeStampOffset)]
			public Int64 TimeStamp;

			[FieldOffset(Layout.IsEncryptedOffset)]
			public bool IsEncrypted;
			[FieldOffset(Layout.SaltOffset)]
			public fixed byte Salt[Layout.SaltSize];

			[FieldOffset(Layout.NameOffset)]
			public fixed byte Name[Layout.NameSize];
			[FieldOffset(Layout.DescriptionOffset)]
			public fixed byte Description[Layout.DescriptionSize];
			[FieldOffset(Layout.LoginOffset)]
			public fixed byte Login[Layout.LoginSize];
			[FieldOffset(Layout.PasswordOffset)]
			public fixed byte Password[Layout.PasswordSize];

			[FieldOffset(Layout.RNGOffset)]
			public fixed byte RNG[Layout.RNGSize];
		}

	}
}
