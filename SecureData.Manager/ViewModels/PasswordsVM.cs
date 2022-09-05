using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using SecureData.Manager.Models;
using SecureData.Manager.Services;
using SecureData.Storage;
using SecureData.Storage.Models;
using SecureData.Storage.Models.Abstract;

namespace SecureData.Manager.ViewModels;

[ObservableObject]
public partial class PasswordsVM
{
	private readonly DatabaseVM _databaseVM;

	//TODO: here hierarchy
	public IReadOnlyObservableList<Data>? Items => _databaseVM.DataItems;

	public PasswordsVM(DatabaseVM databaseVM)
	{
		_databaseVM = databaseVM;
	}

	[RelayCommand()]
	private void Add()
	{

	}
}
