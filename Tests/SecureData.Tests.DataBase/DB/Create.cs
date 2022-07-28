﻿using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class CreateTests
	{
		[Fact]
		public void Create_NoData()
		{
			string path = $"{nameof(Create_NoData)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				byte[] key = new byte[AesCtr.KeySize];
				byte[] iv = new byte[AesCtr.IVSize];
				string login = "MY LOGIN@!#&*@!$*123123;'.lds";
				Random r = new(42);
				r.NextBytes(key);
				r.NextBytes(iv);
				byte[] expected_Hash, actual_Hash;
				string actual_Login;
				using (var db = new SecureData.DataBase.DB(path))
				{
					db.Create(key, iv, login);
					actual_Hash = db.Hash.ToArray();
					actual_Login = db.Login;
				}
				using (var bcs = new BlockCryptoStream(path,
					  new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open }, key, iv))
				{
					byte[] buffer = new byte[bcs.Length];
					bcs.ReadThroughEncryption(buffer.AsSpan(0, DBHeader.Size));
					bcs.Read(buffer.AsSpan(DBHeader.Size));
					expected_Hash = SHA256.ComputeHash(buffer.AsSpan(DBHeader.HashStart));
				}

				Assert.Equal(expected_Hash, actual_Hash);
				Assert.Equal(login, actual_Login);

			}
			finally
			{
				DeleteFile(path);
			}
		}
	}
}