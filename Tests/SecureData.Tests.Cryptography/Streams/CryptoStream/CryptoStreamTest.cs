using SecureData.Cryptography.Streams;

namespace SecureData.Tests.Cryptography.Streams.CryptoStream
{
	public class CryptoStreamTest : IDisposable
	{
		protected const int DataSize = 1024 * 64;
		protected const int Offset = 16;

		protected static readonly byte[] Key, IV, Data, DataEncrypted;
		static CryptoStreamTest()
		{
			Random r = new(42);
			Key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			IV = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			Data = new byte[DataSize];
			DataEncrypted = new byte[DataSize];
			r.NextBytes(Key);
			r.NextBytes(IV);
			r.NextBytes(Data);
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(Key, IV))
			{
				aes.Transform(Data, DataEncrypted, 0);
			}
		}

		protected static byte[] CreateDataCopy() => (byte[])Data.Clone();
		protected static byte[] CreateActualBuffer() => new byte[DataSize];

		protected static BlockCryptoStream BCSOverArray(byte[] array)
			=> new(new MemoryStream(array), Key, IV, true);


		protected readonly SecureData.Cryptography.SymmetricEncryption.AesCtr Aes;
		public CryptoStreamTest()
		{
			Aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(Key, IV);
		}

		public virtual void Dispose()
		{
			Random r = new(42);
			Span<byte> key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			Span<byte> iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			Span<byte> data = new byte[DataSize];
			r.NextBytes(key);
			r.NextBytes(iv);
			r.NextBytes(data);
			if (!key.SequenceEqual(Key))
			{
				throw new Exception("Key corrupted");
			}
			if (!iv.SequenceEqual(IV))
			{
				throw new Exception("IV corrupted");
			}
			if (!data.SequenceEqual(Data))
			{
				throw new Exception("Data corrupted");
			}

			using (var taes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				Span<byte> dataEncrypted = new byte[DataSize];
				taes.Transform(data, dataEncrypted, 0);
				if (!dataEncrypted.SequenceEqual(DataEncrypted))
				{
					throw new Exception("Aes or DataEncrypted corrupted");
				}
			}

			Aes.Dispose();

			GC.SuppressFinalize(this);
		}
	}
}
