using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase
{
	internal class DataSet : IEnumerable<Data>
	{
		private const int MinCacheSize = 16 * 1024;

		private readonly Dictionary<uint, DataInfo> _data = new();
		private readonly LinkedList<DataInfo> _cached = new();
		private readonly int _maxCacheSize;
		private int _currentCacheSize = 0;

		public DataSet(int maxCacheSize)
		{
			if (maxCacheSize < MinCacheSize)
			{
				maxCacheSize = MinCacheSize;
			}
			_maxCacheSize = maxCacheSize;
		}

		public void Add(Data data, long filePos)
		{
			_data.Add(data.Id, new DataInfo(data, filePos));
		}

		public Data this[uint id]
		{
			get => _data[id].Data;
		}

		public bool TryGetValue(uint id, [MaybeNullWhen(false)] out Data? data)
		{
			bool res = _data.TryGetValue(id, out var dataInfo);
			data = dataInfo?.Data;
			return res;
		}

		public bool TryGetCache(Data data, [MaybeNullWhen(false)] out ReadOnlyMemory<byte>? cache)
		{
			var dataInfo = _data[data.Id];
			if (!dataInfo.IsCached)
			{
				cache = null;
				return false;
			}
			cache = dataInfo.GetCache();
			return true;
		}
		public Span<byte> CacheData(Data data)
		{
			var dataInfo = _data[data.Id];
			return dataInfo.CreateCache();
		}

		public IEnumerator<Data> GetEnumerator() => _data.Values.Select(x => x.Data).GetEnumerator();
		IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

		private void EnsureContains(Data data)
		{
			if (!_data.ContainsKey(data.Id))
			{
				throw new UnexpectedException("Set does not contain data.");
			}
		}


		//TODO: cache items while reading first time checking that cache has space
		private class DataInfo
		{
			public Data Data { get; }


			
		}
		private class DataCache
		{
			private byte[]? _arrayPoolBuffer;

			public long FilePos { get; }

			public DataCache(long filePos)
			{
				FilePos = filePos;
			}

			public long GetSensitivePos() => FilePos + Data.SensitiveOffset;
			public uint GetSensitiveCTR() => AesCtr.ConvertToCTR(GetSensitivePos());
			public int GetCacheSize() => Data.Size - Data.SensitiveOffset;

			[MemberNotNullWhen(true, nameof(_arrayPoolBuffer))]
			public bool IsCached => _arrayPoolBuffer is not null;

			public Span<byte> CreateCache()
			{
				EnsureNotCached();
				int cacheSize = GetCacheSize();
				_arrayPoolBuffer = ArrayPool<byte>.Shared.Rent(cacheSize);
				return _arrayPoolBuffer.AsSpan(0, cacheSize);
			}
			public ReadOnlyMemory<byte> GetCache()
			{
				EnsureCached();
				return _arrayPoolBuffer.AsMemory(0, GetCacheSize());
			}
			public void ClearCache()
			{
				EnsureCached();
				ArrayPool<byte>.Shared.Return(_arrayPoolBuffer, false);
				_arrayPoolBuffer = null;
			}

			[MemberNotNull(nameof(_arrayPoolBuffer))]
			private void EnsureCached()
			{
				if (!IsCached)
				{
					throw new InvalidOperationException("Data not cached.");
				}
			}
			private void EnsureNotCached()
			{
				if (IsCached)
				{
					throw new InvalidOperationException("Data already cached.");
				}
			}
		}
	}
}
