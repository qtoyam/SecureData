using CommunityToolkit.Mvvm.ComponentModel;

using SecureData.Manager.Services;
using SecureData.Storage;

namespace SecureData.Manager.ViewModels;

[ObservableObject]
public partial class AppWindowVM
{

	public DatabaseVM DatabaseVM { get; }
	public PasswordsVM PasswordsVM { get; }

	public AppWindowVM(DatabaseVM databaseVM, PasswordsVM passwordsVM)
	{
		DatabaseVM = databaseVM;
		PasswordsVM = passwordsVM;
	}
}