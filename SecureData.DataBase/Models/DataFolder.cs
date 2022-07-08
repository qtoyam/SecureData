namespace SecureData.DataBase.Models
{
	public sealed class DataFolder : IEncryptedData
	{
		public class Layout : IEncryptedData.Layout
		{
			public const int NameOffset = IEncryptedData.Layout.Size;
			public const int NameSize = 64;

			public const int DescriptionOffset = NameOffset + NameSize;
			public const int DescriptionSize = 256;

			public new const int Size = DescriptionOffset + DescriptionSize;

			public const int RNGOffset = Size;
			public const int RNGSize = 11;

			public new const int DBSize = RNGOffset + RNGSize;
		}

		#region IData
		public ReadOnlyMemory<byte> Hash { get; }
		public DataType DataType => DataType.DataFolder;
		public uint Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
		public int DBSize => Layout.DBSize;
		#endregion

		#region IEncryptedData
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		#endregion

		#region DataFolder
		public string Name { get; }
		public string Description { get; }
		#endregion

		#region Other (RAM)
		private readonly Dictionary<uint, IData> _items;
		public int Count => _items.Count;
		#endregion
	}

	public class DataFolderBox : IEncryptedDataBox
	{
		#region IDataBox
		public DataType DataType { get; set; }
		public IData? Parent { get; set; }
		public EncryptionChain? EncryptionChain { get; set; }
		#endregion

		#region IEncryptedDataBox
		public bool IsEncrypted { get; set; }
		public ReadOnlyMemory<byte>? Salt { get; set; }
		public ReadOnlyMemory<byte>? Key { get; set; }
		#endregion

		#region DataFolderBox
		public string Name { get; set; }
		public string Description { get; set; }
		#endregion
	}
}
