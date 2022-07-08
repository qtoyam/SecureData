namespace SecureData.DataBase.Models
{
	public interface IEncryptedData : IData
	{
		public new abstract class Layout : IData.Layout
		{
			public const int IsEncryptedOffset = IData.Layout.Size;
			public const int IsEncryptedSize = sizeof(bool);

			public const int SaltOffset = IsEncryptedOffset + IsEncryptedSize;
			public const int SaltSize = 16;

			protected new const int Size = SaltOffset + SaltSize;
		}

		public bool IsEncrypted { get; }
		public ReadOnlyMemory<byte> Salt { get; }
	}
}
