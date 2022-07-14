using System.Runtime.InteropServices;

namespace SecureData.DataBase.Models
{
	//public sealed class DataFolder : IEncryptedData
	//{
	//	public class Layout : IEncryptedData.Layout
	//	{
	//		public const int NameOffset = IEncryptedData.Layout.Size;
	//		public const int NameSize = 64;

	//		public const int DescriptionOffset = NameOffset + NameSize;
	//		public const int DescriptionSize = 256;

	//		public new const int Size = DescriptionOffset + DescriptionSize; //from IData

	//		public const int RNGOffset = Size;
	//		public const int RNGSize = 10;

	//		public new const int DBSize = RNGOffset + RNGSize; //from LayoutBase
	//		public new const int SelfEncryptStart = RNGOffset; //from IEncryptedData
	//	}

	//	public bool IsVisible { get; private set; }
	//	public bool IsChanged { get; private set; }

	//	private readonly Raw _raw;
	//	public int CopyTo(Span<byte> buffer)
	//	{
	//		ReadOnlySpan<byte> rawBytes = MemoryHelper.StructToReadOnlySpan(in _raw);
	//		rawBytes.CopyTo(buffer);
	//		return rawBytes.Length;
	//	}

	//	public uint Id => _raw.Id;
	//	public DataType DataType => DataType.DataFolder;


	//	[StructLayout(LayoutKind.Explicit, Pack = 1)]
	//	internal unsafe struct Raw
	//	{
	//		[FieldOffset(Layout.HashOffset)]
	//		public fixed byte Hash[Layout.HashSize];
	//		[FieldOffset(Layout.DataTypeOffset)]
	//		public DataType DataType;
	//		[FieldOffset(Layout.IdOffset)]
	//		public UInt32 Id;
	//		[FieldOffset(Layout.ParentIdOffset)]
	//		public UInt32 ParentId;
	//		[FieldOffset(Layout.TimeStampOffset)]
	//		public Int64 TimeStamp;

	//		[FieldOffset(Layout.IsEncryptedOffset)]
	//		public bool IsEncrypted;
	//		[FieldOffset(Layout.SaltOffset)]
	//		public fixed byte Salt[Layout.SaltSize];

	//		[FieldOffset(Layout.NameOffset)]
	//		public fixed byte Name[Layout.NameSize];
	//		[FieldOffset(Layout.DescriptionOffset)]
	//		public fixed byte Description[Layout.DescriptionSize];

	//		[FieldOffset(Layout.RNGOffset)]
	//		public fixed byte RNG[Layout.RNGSize];
	//	}
	//}
}
