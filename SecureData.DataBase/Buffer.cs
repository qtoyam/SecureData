using System.Diagnostics;

using SecureData.Storage.Helpers;

namespace SecureData.Storage
{
	internal class Buffer
	{
		private readonly byte[] _buffer;
		private Memory<byte> _freeMem;
		private LinkedList<Memory<byte>> _allocated = new();

		public Buffer(int size)
		{
			_buffer = new byte[size];
			_freeMem = _buffer;
		}

		public Span<byte> GetSpan(int size) => GetMemory(size).Span;

		public Memory<byte> GetMemory(int size)
		{
			lock (_buffer)
			{
				if (_freeMem.Length >= size)
				{
					Memory<byte> res = _freeMem.Slice(0, size);
					_freeMem = _freeMem.Slice(size);
					return res;
				}
			}
			Memory<byte> allocated = new byte[size];
			lock (_allocated)
			{
				_allocated.AddLast(allocated);
			}
			Debug.WriteLine($"Allocated {size} bytes.");
			return allocated;
		}

		public void ReturnAll()
		{
			lock (_buffer)
			{
				MemoryHelper.ZeroOut(_buffer.AsSpan(0, _buffer.Length - _freeMem.Length));
				_freeMem = _buffer;
			}
			lock(_allocated)
			{
				foreach(Memory<byte> allocated in _allocated)
				{
					MemoryHelper.ZeroOut(allocated.Span);
				}
				_allocated.Clear();
			}
		}
	}
}
