namespace SecureData.DataBase.Models
{
	public sealed class DataFolder : IEncryptedData
	{
		#region IData
		public const int Size = 400;
		public DataType DataType => DataType.DataFolder;
		public uint Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
		#endregion

		#region IEncryptedData
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		public ReadOnlyMemory<byte> Hmac { get; }
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
}
