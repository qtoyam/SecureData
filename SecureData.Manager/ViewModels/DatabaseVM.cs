using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using SecureData.Cryptography.Hash;
using SecureData.Manager.Models;
using SecureData.Manager.Services;
using SecureData.Storage;
using SecureData.Storage.Models.Abstract;

namespace SecureData.Manager.ViewModels;

public delegate void DataBaseChangedHandler();

[ObservableObject]
public partial class DatabaseVM : IDisposable
{
	private readonly ParallelRunner _parallelRunner;
	private readonly Notifier _notifier;
	private readonly UserInteractionService _userInteractionService;

	private DataBase? _database;
	private DataBase? DataBase
	{
		get => _database;
		set
		{
			_database = value;
			OnDataBaseChanged();
		}
	}

	public event DataBaseChangedHandler? DataBaseChanged;

	private ObservableCollectionEx<Data>? _dataItems;

	[NotNullIfNotNull(nameof(DataBase))]
	public IReadOnlyObservableList<Data>? DataItems => _dataItems;

	public DatabaseVM(ParallelRunner parallelRunner, Notifier notifier, UserInteractionService userInteractionService)
	{
		_parallelRunner = parallelRunner;
		_notifier = notifier;
		_userInteractionService = userInteractionService;
	}

	[MemberNotNullWhen(true, nameof(DataBase))]
	public bool HasDatabase => DataBase is not null;

	[NotNullIfNotNull(nameof(DataBase))]
	public bool? IsAuthed => DataBase?.IsAuthed;

	[RelayCommand(CanExecute = nameof(CanAuth), AllowConcurrentExecutions = false)]
	private async Task Auth(string password)
	{
		Debug.Assert(HasDatabase);
		Debug.Assert(IsAuthed is false);
		bool result = false;
		await _parallelRunner.Run(() => result = DataBase.TryInit(password));
		if (result)
		{
			Storage.Helpers.MemoryHelper.Wipe(password);
			OnIsAuthedChanged();
		}
		else
		{
			_notifier.NotifyError("Wrong password.");
		}
	}
	private bool CanAuth(string password) => HasDatabase && (IsAuthed == false) && !string.IsNullOrEmpty(password);

	[RelayCommand(CanExecute = nameof(CanCreateDataBase))]
	private void CreateDataBase()
	{
		Debug.Assert(!HasDatabase);
		if (_userInteractionService.TryCreateDataBase(out var db))
		{
			DataBase = db;
		}
	}
	private bool CanCreateDataBase() => !HasDatabase;

	[RelayCommand(CanExecute = nameof(CanLoadDataBase))]
	private void LoadDataBase()
	{
		Debug.Assert(!HasDatabase);
		try
		{
			if (_userInteractionService.TryGetOpenPath(out var savePath, new GetPathOptions("Load database.")))
			{
				DataBase = new(savePath);
			}
		}
		catch (Exception ex)
		{
			_notifier.NotifyException(ex);
		}
	}
	private bool CanLoadDataBase() => !HasDatabase;

	[RelayCommand(CanExecute = nameof(CanUnloadDataBase))]
	private void UnloadDataBase()
	{
		Debug.Assert(HasDatabase);
		DataBase.Dispose();
		DataBase = null;
	}
	private bool CanUnloadDataBase() => HasDatabase;

	private void OnIsAuthedChanged()
	{
		if(IsAuthed is true)
		{
			Debug.Assert(DataBase is not null); //IsAuthed == true => DataBase not null
			_dataItems = new ObservableCollectionEx<Data>(DataBase.Root);
		}
		else
		{
			_dataItems = null;
		}
		OnPropertyChanged(nameof(DataItems));

		OnPropertyChanged(nameof(IsAuthed));

		AuthCommand.NotifyCanExecuteChanged();
	}
	private void OnDataBaseChanged()
	{
		OnPropertyChanged(nameof(HasDatabase));
		OnIsAuthedChanged();

		CreateDataBaseCommand.NotifyCanExecuteChanged();
		LoadDataBaseCommand.NotifyCanExecuteChanged();
		UnloadDataBaseCommand.NotifyCanExecuteChanged();

		DataBaseChanged?.Invoke();
	}

	public void Dispose()
	{
		_database?.Dispose();
		GC.SuppressFinalize(this);
	}
}
