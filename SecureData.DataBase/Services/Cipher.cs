using SecureData.Cryptography.SymmetricEncryption;

namespace SecureData.DataBase.Services
{
	public sealed class Cipher : IDisposable
	{
		public const int BlockSize = Aes.BlockSize;

		private readonly Aes _aes;
		private bool _isLocal;

		private uint _currentId;

		internal Cipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool isLocal)
		{
			_aes = new Aes(key, iv)
			{
				Counter = 0U
			};
			_isLocal = isLocal;
			_currentId = 0U;
		}

		internal void Reset()
		{
			EnsureLocal();
			_aes.Counter = 0U;
		}

		internal void Reset(uint id)
		{
			EnsureWide();
			_aes.Counter = 0U;
			_aes.MovePrevIV(_currentId);
			_currentId = id;
			_aes.MoveNextIV(_currentId);
		}

		internal Cipher Wide()
		{
			Reset();
			_isLocal = false;
			return this;
		}

		internal Cipher Local()
		{
			Reset(0U);
			_isLocal = true;
			return this;
		}

		public void Transform(ReadOnlySpan<byte> source, Span<byte> destination) => _aes.Transform(source, destination);
		public void Transform(Span<byte> buffer) => _aes.Transform(buffer);

		void IDisposable.Dispose() => _aes.Dispose();

		private void EnsureLocal()
		{
			if(!_isLocal)
			{
				throw new InvalidOperationException("Operation not supported in wide mode.");
			}
		}
		private void EnsureWide()
		{
			if(_isLocal)
			{
				throw new InvalidOperationException("Operation not supported in local mode.");
			}
		}
	}
}
