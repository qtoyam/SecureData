using System.Diagnostics;

using SecureData.Storage.Helpers;

namespace SecureData.Storage.Services
{
	internal class Buffer
	{
		private readonly byte[] _buffer;
		private int _pos = 0;
		private int _sliced = 0;

		public Buffer(int size)
		{
			_buffer = new byte[size];
		}

		public Rented Rent(int size)
		{
			lock (_buffer)
			{
				if (_buffer.Length - _pos >= size)
				{
					//we can return fast
					Rented rented = new(this, _buffer.AsMemory(_pos, size), _pos);
					_pos += size;
					++_sliced;
					return rented;
				}
			}
			Debug.WriteLine($"Allocated {size} bytes.");
			return new Rented(this, new byte[size]);
		}

		private void Return(Rented rented)
		{
			MemoryHelper.Wipe(rented.Span);
			if (!rented.IsAllocated)
			{
				lock (_buffer)
				{
					--_sliced;
					Debug.Assert(_sliced >= 0);
					if (_sliced == 0)
						_pos = 0;
				}
			}
		}

		public sealed class Rented : IDisposable
		{
			private readonly Buffer _buffer;

			internal bool IsAllocated => Pos != 0;
			internal int Pos { get; }

			public Memory<byte> Memory { get; }
			public Span<byte> Span => Memory.Span;

			public Rented(Buffer buffer, Memory<byte> memory, int pos)
			{
				_buffer = buffer;
				Memory = memory;
				Pos = pos;
			}
			public Rented(Buffer buffer, Memory<byte> memory) : this(buffer, memory, 0) { }

			void IDisposable.Dispose() => _buffer.Return(this);
		}
	}
}
