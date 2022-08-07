using System.Collections;
using System.Diagnostics.CodeAnalysis;

using SecureData.Storage.Models;
using SecureData.Storage.Models.Abstract;

namespace SecureData.Storage;

internal class DataSet : IEnumerable<Data>
{
	private bool _isInited = false;

	private record DataInfo(Data Data, long FilePos);

	private readonly Dictionary<uint, DataInfo> _dataSet = new();
	private readonly List<Data> _root = new();

	public IReadOnlyList<Data> Root
	{
		get
		{
			EnsureInited();
			return _root;
		}
	}

	public void Add(Data data, long filePos)
	{
		EnsureInited();
		_dataSet.Add(data.Id, new DataInfo(data, filePos));
		if (!data.HasParent)
		{
			_root.Add(data);
		}
		else
		{
			data.Parent.Add(data);
		}
	}
	internal void AddOnInit(Data data, long filePos)
	{
		EnsureNotInited();
		_dataSet.Add(data.Id, new DataInfo(data, filePos));
	}

	public void Remove(Data data)
	{
		EnsureInited();

		RemoveRec(data);
		if (data.HasParent)
		{
			data.Parent.Remove(data);
		}
		else
		{
			_root.Remove(data);
		}

		void RemoveRec(Data d)
		{
			if(d is FolderData fd)
			{
				foreach(var cd in fd)
				{
					RemoveRec(cd);
				}
			}
			_dataSet.Remove(d.Id);
		}
	}

	internal void FinishInit()
	{
		EnsureNotInited();
		Data.OrganizeHierarchy(this);
		_root.AddRange(this.Where(x => !x.HasParent));
		_isInited = true;
	}

	public Data this[uint id] => _dataSet[id].Data;

	public bool Contains(uint id) => _dataSet.ContainsKey(id);

	public bool TryGetValue(uint id, [MaybeNullWhen(false)] out Data? data)
	{
		EnsureInited();
		bool res = _dataSet.TryGetValue(id, out var dataInfo);
		data = dataInfo?.Data;
		return res;
	}

	public long GetFilePos(Data data) => _dataSet[data.Id].FilePos;

	public IEnumerator<Data> GetEnumerator() => _dataSet.Values.Select(x => x.Data).GetEnumerator();
	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

	private void EnsureInited()
	{
		if (!_isInited)
		{
			throw new InvalidOperationException($"{nameof(DataSet)} is not inited yet.");
		}
	}
	private void EnsureNotInited()
	{
		if (_isInited)
		{
			throw new InvalidOperationException($"{nameof(DataSet)} is already inited.");
		}
	}
}