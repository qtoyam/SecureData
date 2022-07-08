namespace SecureData.DataBase.Models
{
	internal interface IEncryptedData : IData
	{
		public new abstract class Layout : IData.Layout
		{
			public const int IsEncryptedOffset = IData.Layout.Size;
			public const int IsEncryptedSize = sizeof(bool);

			public const int SaltOffset = IsEncryptedOffset + IsEncryptedSize;
			public const int SaltSize = 16;

			protected new const int Size = SaltOffset + SaltSize;
		}


		public bool IsEncrypted { get; set; }
		public ReadOnlyMemory<byte> Salt { get; set; }
	}
	public interface IEncryptedDataBox : IDataBox
	{
		public bool IsEncrypted { get; set; }
		internal Memory<byte> Salt { get; set; }
		internal ReadOnlyMemory<byte> Key { get; set; }
	}
}
