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

			public const int HashingStart = DataTypeOffset;
		}

		//public Memory<byte> Hash { get; set; }
		//public DataType DataType { get; set; }
		public UInt32 Id { get; }
		//public IData? Parent { get; set; }
		//public DateTime TimeStamp { get; set; }

		//public int DBSize { get; }

		//internal ReadOnlySpan<byte> GetRaw();

		/// <summary>
		/// Copy raw data to <paramref name="buffer"/>
		/// </summary>
		/// <param name="buffer"></param>
		/// <returns>Bytes copied.</returns>
		public int CopyTo(Span<byte> buffer);
	}
}
