namespace SecureData.DataBase
{
	internal sealed class ObjectPool<T> : IDisposable
		where T : class
	{
		private readonly Func<T> _create;
		private readonly Action<T> _clear;
		private readonly Action<T> _dispose;

		private readonly LinkedList<T> _free;

		private readonly int _maxObjects;
		private int _inUse = 0;

		private uint _disposed = 0;

		public ObjectPool(int maxObjects, Func<T> create, Action<T> clear, Action<T> dispose)
		{
			_maxObjects = maxObjects;
			_create = create;
			_clear = clear;
			_dispose = dispose;
			_free = new LinkedList<T>();
		}

		public T Rent()
		{
			EnsureNotDisposed();
			T? rented = null;
			lock (_free)
			{
				if (_free.Last is not null)
				{
					rented = _free.Last.Value;
					_free.RemoveLast();
				}
			}
			rented ??= _create();
			Interlocked.Increment(ref _inUse);
			return rented;
		}

		public void Return(T value)
		{
			EnsureNotDisposed();
			if (Interlocked.Decrement(ref _inUse) < 0)
			{
				throw new InvalidOperationException("Returned more objects than rented.");
			}
			_clear(value);
			bool addedToPool = false;
			lock (_free)
			{
				if (_free.Count < _maxObjects)
				{
					_free.AddLast(value);
					addedToPool = true;
				}
			}
			if(!addedToPool)
			{
				_dispose(value);
			}
		}

		private void EnsureNotDisposed()
		{
			if (Interlocked.Add(ref _disposed, 0) != 0)
			{
				throw new ObjectDisposedException(nameof(ObjectPool<T>));
			}
		}

		public void Dispose()
		{
			if(Interlocked.Increment(ref _disposed) != 1)
			{
				throw new ObjectDisposedException(nameof(ObjectPool<T>));
			}
			if (Interlocked.Add(ref _inUse, 0) != 0)
			{
				throw new InvalidOperationException("Not all objects returned.");
			}
			var currentNode = _free.First;
			while(currentNode is not null)
			{
				_dispose(currentNode.Value);
				currentNode = currentNode.Next;
			}
		}
	}
}
