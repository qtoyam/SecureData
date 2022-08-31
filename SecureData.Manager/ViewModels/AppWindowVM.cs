using CommunityToolkit.Mvvm.ComponentModel;

using SecureData.Manager.Services;
using SecureData.Storage;

namespace SecureData.Manager.ViewModels;

[ObservableObject]
public partial class AppWindowVM
{
	private readonly DataBase _db;
	private readonly Notifier _notifier;

	public AuthVM AuthVM { get; }
	public PasswordsVM PasswordsVM { get; }

	public AppWindowVM(DataBase db, Notifier notifier, AuthVM authVM, PasswordsVM passwordsVM)
	{
		_db = db;
		_notifier = notifier;
		AuthVM = authVM;
		PasswordsVM = passwordsVM;
	}
}