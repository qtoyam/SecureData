using SecureData.Cryptography.SymmetricEncryption;

namespace SecureData.DataBase.Helpers
{
	public sealed class EncryptionChain : IDisposable
	{
		private readonly List<Aes256Ctr> _chain;

		public EncryptionChain()
		{
			_chain = new List<Aes256Ctr>(2);
		}
		public void Add(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
		{
			_chain.Add(new Aes256Ctr(key, iv));
		}

		public void Transform(Span<byte> input)
		{
			for (int i = _chain.Count - 1; i >= 0; i--)
			{
				_chain[i].Transform(input, 0U);
			}
		}

		public void Dispose()
		{
			for (int i = 0; i < _chain.Count; i++)
			{
				_chain[i].Dispose();
			}
		}
	}
}
