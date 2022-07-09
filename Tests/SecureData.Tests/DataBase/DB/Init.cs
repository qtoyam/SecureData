using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class InitTests
	{
		[Fact]
		public void Init_NoData()
		{
			string path = $"{nameof(Init_NoData)}TMP0.tmp";
			try
			{
				byte[] fileData = new byte[DBHeader.Layout.DBSize];
				byte[] key = new byte[Aes256Ctr.KeySize];
				byte[] expected_Salt = new byte[Aes256Ctr.IVSize];
				byte[] expected_Hash;
				Random r = new(42);
				r.NextBytes(fileData);
				r.NextBytes(key);
				r.NextBytes(expected_Salt);
				uint expected_Version = BinaryPrimitives.ReadUInt32LittleEndian(fileData.AsSpan(DBHeader.Layout.VersionOffset, DBHeader.Layout.VersionSize));
				//fill with known iv to compare results
				expected_Salt.AsSpan().CopyTo(fileData.AsSpan(DBHeader.Layout.SaltOffset, DBHeader.Layout.SaltSize));
				//fill with valid string cauze encoding is sensetive
				string expected_Login = "MY LOGIN йй123*%№@#!%S\0";
				Encoding.UTF8.GetBytes(expected_Login, fileData.AsSpan(DBHeader.Layout.LoginOffset, DBHeader.Layout.LoginSize));
				expected_Login = expected_Login.Remove(expected_Login.Length - 1);
				expected_Hash = SHA256.ComputeHash(fileData.AsSpan(DBHeader.Layout.HashingStart));
				//fill with valid hash
				expected_Hash.AsSpan().CopyTo(fileData.AsSpan(DBHeader.Layout.HashOffset, DBHeader.Layout.HashSize));
				using (Aes256Ctr aes = new(key, expected_Salt))
				{
					aes.Transform(fileData.AsSpan(DBHeader.Layout.RNGOffset),
						   DBHeader.Layout.RNGOffset / Aes256Ctr.BlockSize);
				}
				File.WriteAllBytes(path, fileData);

				using (var db = SecureData.DataBase.DB.Init(path, key))
				{
					var raw = db._header.GetRawDebug();
					AssertExt.Equal(expected_Hash, DBHeader.GetHashDebug(raw)); //hash
					Assert.Equal(expected_Version, db._header.Version); //version
					AssertExt.Equal(expected_Salt, DBHeader.GetSaltDebug(raw)); //salt
					Assert.Equal(expected_Login, db._header.Login); //login
				}
			}
			finally
			{
				if (File.Exists(path))
				{
					File.Delete(path);
				}
			}
		}

		[Fact]
		public void Init_WrongHash()
		{
			string path = $"{nameof(Init_WrongHash)}.tmp";
			try
			{
				byte[] fileData = new byte[DBHeader.Layout.DBSize];
				File.WriteAllBytes(path, fileData);
				Assert.Throws<SecureData.DataBase.Exceptions.DataBaseWrongHashException>(
					  () =>
					  SecureData.DataBase.DB.Init(path, new byte[Aes256Ctr.KeySize]).Dispose()
					  );
			}
			finally
			{
				if (File.Exists(path))
				{
					File.Delete(path);
				}
			}
		}
	}
}
