namespace SecureData.DataBase.Models
{
	public sealed class AccountData : IEncryptedData
	{
		#region IData
		public const int Size = 464;
		public DataType DataType => DataType.AccountData;
		public uint Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
		#endregion

		#region IEncryptedData
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		public ReadOnlyMemory<byte> Hmac { get; }
		#endregion

		#region AccountData
		public string Name { get; }
		/// <summary>
		/// Encrypted
		/// </summary>
		public ReadOnlyMemory<byte> Login { get; }
		/// <summary>
		/// Encrypted
		/// </summary>
		public ReadOnlyMemory<byte> Password { get; }
		public string Description { get; }
		#endregion
	}
}
