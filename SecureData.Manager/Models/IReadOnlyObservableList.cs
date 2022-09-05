using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;

namespace SecureData.Manager.Models;

public interface IReadOnlyObservableList<T> : INotifyPropertyChanged, INotifyCollectionChanged, IList<T>, IReadOnlyList<T>
{
	
}
