﻿using System;

using SecureData.Cryptography;
using SecureData.Cryptography.SymmetricEncryption;
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
			Key = new byte[Aes256Ctr.KeySize];
			IV = new byte[Aes256Ctr.IVSize];
			Data = new byte[DataSize];
			DataEncrypted = new byte[DataSize];
			r.NextBytes(Key);
			r.NextBytes(IV);
			r.NextBytes(Data);
			using (var aes = new Aes256Ctr(Key, IV))
			{
				aes.Transform(Data, DataEncrypted, 0);
			}
		}

		protected static byte[] CreateDataCopy() => (byte[])Data.Clone();
		protected static byte[] CreateActualBuffer() => new byte[DataSize];

		protected static BlockCryptoStream BCSOverArray(byte[] array)
			=> new(new MemoryStream(array), Key, IV, true);


		protected readonly Aes256Ctr Aes;
		public CryptoStreamTest()
		{
			Aes = new Aes256Ctr(Key, IV);
		}

		public virtual void Dispose()
		{
			Random r = new(42);
			Span<byte> key = new byte[Aes256Ctr.KeySize];
			Span<byte> iv = new byte[Aes256Ctr.IVSize];
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

			using (var taes = new Aes256Ctr(key, iv))
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
