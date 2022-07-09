using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIO
{
	internal static class DBHeaderIO
	{
		public static void FillRNG(BlockCryptoStream bcs, Span<byte> s_buffer, SHA256 sha256)
		{
			bcs.Position = DBHeader.Layout.RNGOffset;
			if (s_buffer.Length >= DBHeader.Layout.RNGSize) //we can fit rng into buffer
			{
				s_buffer = s_buffer.Slice(0, DBHeader.Layout.RNGSize);
				MemoryHelper.RNG(s_buffer);
				sha256.Transform(s_buffer);
				bcs.WriteFast(s_buffer);
			}
			else
			{
				int remainingRNG = DBHeader.Layout.RNGSize;
				//loop full m_buffer's size blocks
				for (; remainingRNG > s_buffer.Length; remainingRNG -= s_buffer.Length)
				{
					MemoryHelper.RNG(s_buffer);
					sha256.Transform(s_buffer);
					bcs.WriteFast(s_buffer);
				}
				// if m_buffer's size is not multiple of DBHeader's size
				if (remainingRNG > 0)
				{
					Span<byte> s_remaining = s_buffer.Slice(0, remainingRNG);
					MemoryHelper.RNG(s_remaining);
					sha256.Transform(s_remaining);
					bcs.WriteFast(s_remaining);
				}
			}
		}
		public static void Write(BlockCryptoStream bcs, ReadOnlySpan<byte> s_dbHeader)
		{
			bcs.Position = 0;
			bcs.WriteThroughEncryption(s_dbHeader);
		}
		public static void WriteHash(BlockCryptoStream bcs, ReadOnlySpan<byte> hash)
		{
			bcs.Position = DBHeader.Layout.HashOffset;
			bcs.WriteThroughEncryption(hash);
		}
		public static void ComputeHash(ReadOnlySpan<byte> s_dbHeader, SHA256 sha256)
		{
			sha256.Transform(s_dbHeader.Slice(DBHeader.Layout.HashingStart));
		}

		//public static async Task ComputeDBHeaderHashAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		//{
		//	bcs.Position = DBHeader.Layout.HashingStart;
		//	{
		//		Memory<byte> m_noEncryptBuffer = m_buffer.Slice(0, DBHeader.Layout.EncryptionStart);
		//		bcs.ReadThroughEncryption(m_noEncryptBuffer.Span);
		//		sha256.Transform(m_noEncryptBuffer.Span);
		//	}
		//	await ComputeRNGHashAsync(bcs, m_buffer, sha256).ConfigureAwait(false);
		//}
		public static void ComputeRNGHash(BlockCryptoStream bcs, Span<byte> s_buffer, SHA256 sha256)
		{
			bcs.Position = DBHeader.Layout.RNGOffset;
			int fullRuns = DBHeader.Layout.RNGSize / s_buffer.Length;
			for (int i = 0; i < fullRuns; i++)
			{
				bcs.Read(s_buffer);
				sha256.Transform(s_buffer);
			}
			//note: if buffer.length > RNGSize, this will be equal to RNGSize
			int remainingRunSize = DBHeader.Layout.RNGSize % s_buffer.Length;
			if (remainingRunSize > 0)
			{
				Span<byte> s_remainingRun = s_buffer.Slice(0, remainingRunSize);
				bcs.Read(s_remainingRun);
				sha256.Transform(s_remainingRun);
			}
		}

	}
}
