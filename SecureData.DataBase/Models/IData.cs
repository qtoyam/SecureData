namespace SecureData.DataBase.Models
{
	internal interface IData
	{
		public abstract class Layout : LayoutBase
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

			protected const int Size = TimeStampOffset + TimeStampSize;

			public const int HashingStart = DataTypeOffset;
		}


		public Memory<byte> Hash { get; set; }
		public DataType DataType { get; set; }
		public UInt32 Id { get; set; }
		public IData? Parent { get; set; }
		public DateTime TimeStamp { get; set; }

		public int DBSize { get; }
	}
	public interface IDataBox
	{
		internal IData? Original { get; set; }
		internal UInt32 Id { get; set; }
		public DataType DataType { get; }
		public IDataBox? Parent { get; set; }
		public DateTime TimeStamp { get; set; }
		public EncryptionChain? EncryptionChain { get; set; }
	}
}
