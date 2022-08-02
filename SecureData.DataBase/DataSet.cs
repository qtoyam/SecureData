﻿using System.Collections;
using System.Diagnostics.CodeAnalysis;

using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase;

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

	public void Add(Data data, long filePos, ReadOnlySpan<byte> dataBytes)
	{
		EnsureInited();
		_dataSet.Add(data.Id, new DataInfo(data, filePos));
		if (!data.HasParent)
		{
			_root.Add(data);
		}
	}
	internal void AddOnInit(Data data, long filePos)
	{
		EnsureNotInited();
		_dataSet.Add(data.Id, new DataInfo(data, filePos));
	}

	internal void FinishInit()
	{
		EnsureNotInited();
		_root.AddRange(this.Where(x => !x.HasParent));
		_isInited = true;
	}

	public Data this[uint id] => _dataSet[id].Data;

	public bool TryGetValue(uint id, [MaybeNullWhen(false)] out Data? data)
	{
		EnsureInited();
		bool res = _dataSet.TryGetValue(id, out var dataInfo);
		data = dataInfo?.Data;
		return res;
	}

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
//TODO: cache items while reading first time checking that cache has space
