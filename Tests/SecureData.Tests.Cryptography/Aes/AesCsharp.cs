using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecureData.Tests.Cryptography.Aes
{
	//only little endian
	internal sealed class AesCsharp : IDisposable
	{
		private readonly ICryptoTransform _aes;
		private readonly byte[] _iv;

		public AesCsharp(byte[] key, byte[] iv)
		{
			using (var aes = System.Security.Cryptography.Aes.Create())
			{
				aes.BlockSize = SecureData.Cryptography.SymmetricEncryption.AesCtr.BlockSize * 8;
				aes.KeySize = SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize * 8;
				aes.Mode = CipherMode.ECB;
				aes.Padding = PaddingMode.None;
				_aes = aes.CreateEncryptor(key, null);
			}
			_iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			for (int i = 0; i < SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize; i++)
			{
				_iv[i] = iv[i];
			}
		}

		public void Transform(byte[] input, byte[] output, uint initialCounter)
		{
			byte[] tiv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			for (int i = 0; i < SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize; i++)
			{
				tiv[i] = _iv[i];
			}
			AddCounter(tiv, initialCounter);
			// encrypt all counters
			for (int offset = 0; offset < input.Length; offset += SecureData.Cryptography.SymmetricEncryption.AesCtr.BlockSize)
			{
				_aes.TransformBlock(tiv, 0, SecureData.Cryptography.SymmetricEncryption.AesCtr.BlockSize, output, offset);
				IncrCounter(tiv);
			}
			// xor all input and output(encrypted counters)
			for (int xori = 0; xori < input.Length; xori++)
			{
				output[xori] ^= input[xori];
			}
		}

		private static void IncrCounter(byte[] iv)
		{
			var iv_uints = MemoryMarshal.Cast<byte, uint>(iv);
			++iv_uints[^1];
		}
		private static void AddCounter(byte[] iv, uint addedValue)
		{
			var iv_uints = MemoryMarshal.Cast<byte, uint>(iv);
			iv_uints[^1] += addedValue;
		}

		public void Dispose() => _aes.Dispose();
	}
}
