using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using SecureData.Storage;
using SecureData.Storage.Models;

namespace SecureData.Manager.ViewModels;

[ObservableObject]
public partial class PasswordsVM
{
	private readonly DataBase _db;

	public ObservableCollection<DataVM> Items { get; }

	public PasswordsVM(DataBase db)
	{
		_db = db;
		Items = new(_db.Root.Where(x => x is AccountData || x is FolderData).Cast<DataVM>());
	}

	[RelayCommand()]
	private void InitAdd()
	{

	}
}
