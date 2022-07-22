using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase.Models
{
	public class AccountData : Data
	{
		private static class Layout
		{
			public const int NameOffset = Data.SizeConst;
			public const int NameSize = 128;

			public const int DescriptionOffset = NameOffset + NameSize;
			public const int DescriptionSize = 256;

			public const int LoginOffset = DescriptionOffset + DescriptionSize;
			public const int LoginSize = 128;

			public const int PasswordOffset = LoginOffset + LoginSize;
			public const int PasswordSize = 128;
		}
		protected new const int SizeConst = Layout.PasswordOffset + Layout.PasswordSize;
		protected new const uint DataTypeConst = 1U;
		#region DB
		#region Private write-access
		private string _name = string.Empty;
		private string _description = string.Empty;
		private string _login = string.Empty;
		private string _password = string.Empty;

		#endregion
		public override uint DataType => DataTypeConst;

		public string Name
		{
			get => Get(ref _name);
			set => Set(ref _name, value);
		}
		public string Description
		{
			get => Get(ref _description);
			set => Set(ref _description, value);
		}
		public string Login
		{
			get => GetSensitive(ref _login);
			set => Set(ref _login, value);
		}
		public string Password
		{
			get => GetSensitive(ref _password);
			set => Set(ref _password, value);
		}
		#endregion

		protected AccountData(Memory<byte> raw) : base(raw, false) { }

		public AccountData() : base(new byte[SizeConst], true) { }

		public override int Size => SizeConst;
		protected override int ObjectCipherStart => Layout.LoginOffset;


		protected override void UpdateData(ReadOnlySpan<byte> raw)
		{
			base.UpdateData(raw);
			_name = BinaryHelper.ReadString(raw.Slice(Layout.NameOffset, Layout.NameSize));
			_description = BinaryHelper.ReadString(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize));
		}
		protected override void UpdateSensitiveData(ReadOnlySpan<byte> raw)
		{
			base.UpdateSensitiveData(raw);
			_login = BinaryHelper.ReadString(raw.Slice(Layout.LoginOffset - ObjectCipherStart, Layout.LoginSize));
			_password = BinaryHelper.ReadString(raw.Slice(Layout.PasswordOffset - ObjectCipherStart, Layout.PasswordSize));
		}

		protected override void FlushAll(Span<byte> raw)
		{
			base.FlushAll(raw);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.NameOffset, Layout.NameSize), _name);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize), _description);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.LoginOffset, Layout.LoginSize), _login);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.PasswordOffset, Layout.PasswordSize), _password);
		}

		protected override void ClearData()
		{
			base.ClearData();
			_name = string.Empty;
			_description = string.Empty;
		}

		protected override void ClearSensitiveData()
		{
			base.ClearSensitiveData();
			_login = string.Empty;
			_password = string.Empty;
		}
	}
}
