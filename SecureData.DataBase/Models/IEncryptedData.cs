namespace SecureData.DataBase.Models
{
	internal interface IEncryptedData : IData
	{
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		public ReadOnlyMemory<byte> Hmac { get; }
	}
}
