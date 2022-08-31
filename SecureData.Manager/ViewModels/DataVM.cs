using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Storage.Models.Abstract;

namespace SecureData.Manager.ViewModels;

public class DataVM : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;
	public Data Value { get; }

	public DataVM(Data value)
	{
		Value = value;
	}

	public void Updated()
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Value)));
	}

	public static implicit operator Data(DataVM vm) => vm.Value;
	public static implicit operator DataVM(Data data) => new(data);
}
