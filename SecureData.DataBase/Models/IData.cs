namespace SecureData.DataBase.Models
{
	public interface IData
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
		}

		public ReadOnlyMemory<byte> Hash { get; }
		public DataType DataType { get; }
		public UInt32 Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
	}
}
