using System.Threading.Tasks;

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using SecureData.Manager.Services;
using SecureData.Storage;

namespace SecureData.Manager.ViewModels;

public partial class AuthVM : ObservableObject
{
	private readonly DataBase _db;
	private readonly Notifier _notifier;
	private readonly ParallelRunner _parallelRunner;

	public AuthVM(DataBase db, Notifier notifier, ParallelRunner parallelRunner)
	{
		_db = db;
		_notifier = notifier;
		IsAuthed = _db.IsAuthed;
		_parallelRunner = parallelRunner;
	}

	[ObservableProperty]
	[NotifyCanExecuteChangedFor(nameof(AuthCommand))]
	private string? _password;

	[ObservableProperty]
	private bool _isAuthed = false;

	[RelayCommand(CanExecute = nameof(CanAuth), AllowConcurrentExecutions = false)]
	private async Task Auth()
	{
		bool result = false;
		await _parallelRunner.Run(() => result = _db.TryInit(Password!));
		if (result)
		{
			Storage.Helpers.MemoryHelper.Wipe(_password!);
			Password = null;
			IsAuthed = true;
		}
		else
		{
			_notifier.NotifyError("Wrong password.");
		}
	}

	private bool CanAuth() => !string.IsNullOrEmpty(_password);
}
