namespace SecureData.DataBase.Models
{
	public sealed class AccountData : IEncryptedData
	{
		public class Layout : IEncryptedData.Layout
		{
			public const int NameOffset = IEncryptedData.Layout.Size;
			public const int NameSize = 128;

			public const int LoginOffset = NameOffset + NameSize;
			public const int LoginSize = 128;

			public const int PasswordOffset = LoginOffset + LoginSize;
			public const int PasswordSize = 128;

			public const int DescriptionOffset = PasswordOffset + PasswordSize;
			public const int DescriptionSize = 256;

			public new const int Size = DescriptionOffset + DescriptionSize;

			public const int RNGOffset = Size;
			public const int RNGSize = 11;

			public new const int DBSize = RNGOffset + RNGSize;
		}

		#region IData
		public ReadOnlyMemory<byte> Hash { get; }
		public DataType DataType => DataType.AccountData;
		public uint Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
		#endregion

		#region IEncryptedData
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		#endregion

		#region AccountData
		public string Name { get; } = "TEMP";
		/// <summary>
		/// Encrypted
		/// </summary>
		public ReadOnlyMemory<byte> Login { get; }
		/// <summary>
		/// Encrypted
		/// </summary>
		public ReadOnlyMemory<byte> Password { get; }
		public string Description { get; } = "TEMP";
		#endregion
	}
}
