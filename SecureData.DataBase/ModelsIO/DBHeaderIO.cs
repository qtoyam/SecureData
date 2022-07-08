using System;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIO
{
	internal static class DBHeaderIO
	{
		public static DBHeader Read(Stream stream, Span<byte> s_buffer, SHA256 sha256)
		{
			s_buffer = s_buffer.Slice(0, DBHeader.Layout.Size);
			if (stream.Length < DBHeader.Layout.DBSize)
			{
				throw DataBaseCorruptedException.WrongDBHeader();
			}
			//assume dbheader always starts at 0 pos
			stream.Position = 0;
			stream.Read(s_buffer);

			//hash data from dbheader (without RNG)
			//note: not worth parallel, cauze low size
			sha256.Transform(s_buffer.Slice(DBHeader.Layout.HashingStart));
			Memory<byte> hash = new byte[DBHeader.Layout.HashSize];
			s_buffer.Slice(DBHeader.Layout.HashOffset, DBHeader.Layout.HashSize).CopyTo(hash.Span);

			uint version = BitConverter.ToUInt32(s_buffer.Slice(DBHeader.Layout.VersionOffset));

			Memory<byte> salt = new byte[DBHeader.Layout.SaltSize];
			s_buffer.Slice(DBHeader.Layout.SaltOffset, DBHeader.Layout.SaltSize).CopyTo(salt.Span);

			string login = StringHelper.GetStringFromNullTerminatedBytes(
				  s_buffer.Slice(DBHeader.Layout.LoginOffset, DBHeader.Layout.LoginSize));

			return new DBHeader(hash, version, salt, login);
		}
		public static async ValueTask ReadRNGAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		{
			bcs.Position = DBHeader.Layout.RNGOffset;
			int fullRuns = DBHeader.Layout.RNGSize / m_buffer.Length;
			for (int i = 0; i < fullRuns; i++)
			{
				await bcs.ReadAsync(m_buffer).ConfigureAwait(false);
				sha256.Transform(m_buffer.Span);
			}
			//note: if buffer.length > RNGSize, this will be equal to RNGSize
			int remainingRunSize = DBHeader.Layout.RNGSize % m_buffer.Length;
			if (remainingRunSize > 0)
			{
				Memory<byte> remainingRun = m_buffer.Slice(0, remainingRunSize);
				await bcs.ReadAsync(remainingRun).ConfigureAwait(false);
				sha256.Transform(remainingRun.Span);
			}
		}
		public static void WriteReal(BlockCryptoStream bcs, DBHeader dbHeader, Span<byte> s_buffer, SHA256 sha256)
		{
			bcs.Position = 0;
			s_buffer = s_buffer.Slice(0, DBHeader.Layout.Size);
			BinaryHelper.Write(s_buffer.Slice(DBHeader.Layout.HashOffset), dbHeader.Hash.Span); //hash
			BinaryHelper.WriteUInt32(s_buffer.Slice(DBHeader.Layout.VersionOffset), dbHeader.Version); //version
			BinaryHelper.Write(s_buffer.Slice(DBHeader.Layout.SaltOffset), dbHeader.Salt.Span); //salt
			StringHelper.Write(s_buffer.Slice(DBHeader.Layout.LoginOffset),
				dbHeader.Login, DBHeader.Layout.LoginSize); //login

			sha256.Transform(s_buffer.Slice(DBHeader.Layout.HashingStart));
			bcs.WriteThroughEncryption(s_buffer);
		}
		public static async Task WriteRNGAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		{
			bcs.Position = DBHeader.Layout.RNGOffset;
			if (m_buffer.Length > DBHeader.Layout.RNGSize) //we can fit rng into buffer
			{
				m_buffer = m_buffer.Slice(0, DBHeader.Layout.RNGSize);
				Utils.RNG(m_buffer.Span);
				sha256.Transform(m_buffer.Span);
				await bcs.WriteFastAsync(m_buffer).ConfigureAwait(false);
			}
			else
			{
				int remainingRNG = DBHeader.Layout.RNGSize;
				//loop full m_buffer's size blocks
				for (; remainingRNG > m_buffer.Length; remainingRNG -= m_buffer.Length)
				{
					Utils.RNG(m_buffer.Span);
					sha256.Transform(m_buffer.Span);
					await bcs.WriteFastAsync(m_buffer).ConfigureAwait(false);
				}
				// if m_buffer's size is not multiple of DBHeader's size
				if (remainingRNG > 0)
				{
					Memory<byte> m_remaining = m_buffer.Slice(0, remainingRNG);
					Utils.RNG(m_remaining.Span);
					sha256.Transform(m_remaining.Span);
					await bcs.WriteFastAsync(m_remaining).ConfigureAwait(false);
				}
			}
		}

		public static void WriteHash(BlockCryptoStream bcs, DBHeader dbHeader)
		{
			bcs.Position = DBHeader.Layout.HashOffset;
			bcs.WriteThroughEncryption(dbHeader.Hash.Span);
		}
	}
}
