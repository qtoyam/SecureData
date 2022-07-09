namespace SecureData.DataBase.Models
{
	public interface IEncryptedData : IData
	{
		public new abstract class Layout : IData.Layout
		{
			public const int IsEncryptedOffset = IData.Layout.Size;
			public const int IsEncryptedSize = 2; //1 byte padding

			public const int SaltOffset = IsEncryptedOffset + IsEncryptedSize;
			public const int SaltSize = 16;

			protected new const int Size = SaltOffset + SaltSize;
			protected const int EncryptionStart = -1;
		}


		//public bool IsEncrypted { get; set; }
		//public ReadOnlyMemory<byte> Salt { get; set; }
	}
}
