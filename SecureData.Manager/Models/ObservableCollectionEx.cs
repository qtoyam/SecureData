using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;

namespace SecureData.Manager.Models;

public class ObservableCollectionEx<T> : ObservableCollection<T>, IReadOnlyObservableList<T>
{
	public ObservableCollectionEx() : base() { }
	public ObservableCollectionEx(IEnumerable<T> collection) : base(collection) { }
	public ObservableCollectionEx(List<T> list) : base(list) { }

	public void AddRange(IEnumerable<T> newItems)
	{
		CheckReentrancy();
		int index = Count;
		if (newItems is not IList<T> newItemsList)
		{
			newItemsList = newItems.ToList();
		}
		if (Items is List<T> itemsList)
		{
			itemsList.AddRange(newItemsList);
		}
		else
		{
			for (int i = 0; i < newItemsList.Count; i++)
			{
				Items.Add(newItemsList[i]);
			}
		}
		OnPropertyChanged(EventArgsCache.CountPropertyChanged);
		OnPropertyChanged(EventArgsCache.IndexerPropertyChanged);
		OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, newItemsList, index));
	}

	private static class EventArgsCache
	{
		internal static readonly PropertyChangedEventArgs CountPropertyChanged = new("Count");
		internal static readonly PropertyChangedEventArgs IndexerPropertyChanged = new("Item[]");
	}
}
