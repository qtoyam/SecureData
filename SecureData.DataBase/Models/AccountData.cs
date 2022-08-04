using SecureData.Storage.Helpers;
using SecureData.Storage.Models.Abstract;

namespace SecureData.Storage.Models;

public class AccountData : Data
{
	private static class Layout
	{
		public const int LoginOffset = Data.SizeConst;
		public const int LoginSize = 128;

		public const int PasswordOffset = LoginOffset + LoginSize;
		public const int PasswordSize = 128;
	}
	protected new const int SizeConst = Layout.PasswordOffset + Layout.PasswordSize;
	protected new const long DataTypeConst = 1U;
	protected new const int SensitiveOffsetConst = Layout.LoginOffset;

	#region DB
	#region Private write-access
	private string? _login;
	private string? _password;
	#endregion
	public override long DataType => DataTypeConst;
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

	protected AccountData(ReadOnlySpan<byte> raw) : base(raw) { }
	public AccountData() : base()
	{
		_login = _password = string.Empty;
	}

	public override int Size => SizeConst;
	public override int SensitiveOffset => SensitiveOffsetConst;

	protected override void ClearSensitiveCore()
	{
		_login = _password = null;
	}

	protected override void LoadSensitiveCore(ReadOnlySpan<byte> sensitiveBytes)
	{
		_login = BinaryHelper.ReadString(sensitiveBytes.Slice(Layout.LoginOffset - SensitiveOffset, Layout.LoginSize));
		_password = BinaryHelper.ReadString(sensitiveBytes.Slice(Layout.PasswordOffset - SensitiveOffset, Layout.PasswordSize));
	}

	protected override void FlushCore(Span<byte> raw)
	{
		BinaryHelper.WriteStringWithRNG(raw.Slice(Layout.LoginOffset, Layout.LoginSize), Login);
		BinaryHelper.WriteStringWithRNG(raw.Slice(Layout.PasswordOffset, Layout.PasswordSize), Password);
	}
}
