namespace SecureData.Tests.Cryptography.Aes
{
	public class TransformTests
	{
		private const int KB = 1024;
		private const int MB = KB * 1024;

		private static void RandomBuffers(int seed, params byte[][] buffers)
		{
			Random r = new(seed);
			foreach (var b in buffers)
			{
				r.NextBytes(b);
			}
		}

		[Fact]
		public void TransformBlock()
		{
			TestBlock(0);
		}
		[Fact]
		public void TransformBlock_InitCtrHalfMax()
		{
			TestBlock(uint.MaxValue / 2);
		}
		[Fact]
		public void TransformBlock_InitCtrMax()
		{
			TestBlock(uint.MaxValue);
		}

		[Fact]
		public void Transform16B()
		{
			Test(16, 0);
		}
		[Fact]
		public void Transform16KB()
		{
			Test(16 * KB, 0);
		}
		[Fact]
		public void Transform16MB()
		{
			Test(16 * MB, 0);
		}

		[Fact]
		public void Transform16MB_InPlace()
		{
			const int size = 16 * MB;
			const uint initCounter = 0;
			byte[] data = new byte[size];
			byte[] key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			byte[] iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			byte[] expected = new byte[size];
			RandomBuffers(42, data, key, iv);
			using (var aesCsharp = new AesCsharp(key, iv))
			{
				aesCsharp.Transform(data, expected, initCounter);
			}

			byte[] actual = data;
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.Transform(actual, initCounter);
			}

			Assert.Equal(expected, actual);
		}
		[Fact]
		public void Transform16MB_InPlace_Overlaped()
		{
			const int size = 16 * MB;
			const uint initCounter = 0;
			byte[] data = new byte[size];
			byte[] key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			byte[] iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			byte[] expected = new byte[size];
			RandomBuffers(42, data, key, iv);
			using (var aesCsharp = new AesCsharp(key, iv))
			{
				aesCsharp.Transform(data, expected, initCounter);
			}

			byte[] actual = data;
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.Transform(data, actual, initCounter);
			}

			Assert.Equal(expected, actual);
		}

		[Fact]
		public void Transform16MB_InitCtrMax()
		{
			Test(16 * MB, uint.MaxValue);
		}
		[Fact]
		public void Transform16MB_InitCtrHalfMax()
		{
			Test(16 * MB, uint.MaxValue / 2);
		}

		[Fact]
		public void EncryptDecrypt16MB()
		{
			const int size = 16 * MB;
			const uint initCounter = 0;
			byte[] data = new byte[size];
			byte[] key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			byte[] iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			byte[] expected = new byte[size];
			RandomBuffers(42, data, key, iv);
			data.CopyTo((Span<byte>)expected);

			byte[] actual = data;
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.Transform(actual, initCounter);
			}
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.Transform(actual, initCounter);
			}

			Assert.Equal(expected, actual);
		}

		private static void Test(int size, uint initCounter)
		{
			byte[] data = new byte[size];
			byte[] key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			byte[] iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			byte[] expected = new byte[size];
			RandomBuffers(42, data, key, iv);
			using (var aesCsharp = new AesCsharp(key, iv))
			{
				aesCsharp.Transform(data, expected, initCounter);
			}

			byte[] actual = new byte[size];
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.Transform(data, actual, initCounter);
			}

			Assert.Equal(expected, actual);
		}
		private static void TestBlock(uint initCounter)
		{
			const int size = SecureData.Cryptography.SymmetricEncryption.AesCtr.BlockSize;
			byte[] data = new byte[size];
			byte[] key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			byte[] iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			byte[] expected = new byte[size];
			RandomBuffers(42, data, key, iv);
			using (var aesCsharp = new AesCsharp(key, iv))
			{
				aesCsharp.Transform(data, expected, initCounter);
			}

			byte[] actual = new byte[size];
			using (var aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr(key, iv))
			{
				aes.TransformBlock(data, actual, initCounter);
			}

			Assert.Equal(expected, actual);
		}
	}
}
