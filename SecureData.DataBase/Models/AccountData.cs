//using SecureData.Cryptography.SymmetricEncryption;
//using SecureData.DataBase.Models.Abstract;

//namespace SecureData.DataBase.Models
//{
//	internal sealed class AccountData : EncryptedData
//	{
//		public new class Layout : EncryptedData.Layout
//		{
//			public const int NameOffset = EncryptedData.Layout.Size;
//			public const int NameSize = 128;

//			public const int DescriptionOffset = NameOffset + NameSize;
//			public const int DescriptionSize = 256;

//			public const int LoginOffset = DescriptionOffset + DescriptionSize;
//			public const int LoginSize = 128;

//			public const int PasswordOffset = LoginOffset + LoginSize;
//			public const int PasswordSize = 128;

//			public new const int Size = PasswordOffset + PasswordSize; //from IData

//			public const int RNGOffset = Size;
//			public const int RNGSize = 10;

//			public new const int DBSize = RNGOffset + RNGSize; //from LayoutBase
//		}
//		internal override int Size => Layout.Size;
//		internal override int SelfEncryptStart => Layout.LoginOffset;

//		public string Name { get; private set; }
//		public string Description { get; private set; }
//		public string Login { get; private set; }
//		public string Password { get; private set; }

//		protected override unsafe void UpdateCore(byte* rawMemory_ptr)
//		{
//			base.UpdateCore(rawMemory_ptr);
//			Name = BinaryHelper.ReadString(rawMemory_ptr, Layout.NameOffset);
//			Description = BinaryHelper.ReadString(rawMemory_ptr, Layout.DescriptionOffset);
//		}

//		protected override unsafe void UpdateSensitiveData(byte* rawMemory_ptr)
//		{
//			Login = BinaryHelper.ReadString(rawMemory_ptr, Layout.LoginOffset);
//			Password = BinaryHelper.ReadString(rawMemory_ptr, Layout.PasswordOffset);
//		}

//		protected override void LockCore(AesCTR ctr)
//		{
//			Login = string.Empty; //TODO: clear memory from string somehow
//			Password = string.Empty;
//		}

//		internal AccountData() : base()
//		{
//			Name = Description = Login = Password = string.Empty;
//		}
//	}
//}
