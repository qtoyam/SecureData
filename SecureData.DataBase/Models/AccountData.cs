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


			public new const int Size = PasswordOffset + PasswordSize;

			public const int RNGOffset = Size;
			public const int RNGSize = 11;

			public new const int DBSize = RNGOffset + RNGSize;
		}

		#region IData
		public Memory<byte> Hash { get; }
		public DataType DataType => DataType.AccountData;
		public uint Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }

		public int DBSize => Layout.DBSize;
		#endregion

		#region IEncryptedData
		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
		#endregion

		#region AccountData
		public string Name { get; }
		public string Description { get; }
		public Memory<byte> Login { get; }
		public Memory<byte> Password { get; }
		#endregion

		public AccountData(Memory<byte> hash, uint id, IData? parent, DateTime timeStamp, bool isEncrypted, ReadOnlyMemory<byte> salt,
			string name, string description, Memory<byte> login, Memory<byte> password)
		{
			Hash = hash;
			Id = id;
			Parent = parent;
			TimeStamp = timeStamp;
			IsEncrypted = isEncrypted;
			Salt = salt;
			Name = name;
			Description = description;
			Login = login;
			Password = password;
		}
	}

	public sealed class AccountDataBox : IEncryptedDataBox
	{
		#region IDataBox
		public DataType DataType { get; }
		public uint Id { get; set; }
		public IDataBox? Parent { get; set; }
		public EncryptionChain? EncryptionChain { get; set; }
		#endregion

		#region IEncryptedDataBox
		public bool IsEncrypted { get; set; }
		public Memory<byte> Salt { get; set; }
		public ReadOnlyMemory<byte> Key { get; set; }
		#endregion

		#region AccountDataBox
		public string Name { get; set; }
		public string Login { get; set; }
		public string Password { get; set; }
		public string Description { get; set; }
		public DateTime TimeStamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

		IData? IDataBox.Original { get; set; }
		#endregion
	}
}
