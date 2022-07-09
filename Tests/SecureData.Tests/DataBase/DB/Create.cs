using System.Text;

using SecureData.Cryptography.Hash;
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
			try
			{
				byte[] key = new byte[Aes256Ctr.KeySize];
				byte[] expected_Salt = new byte[DBHeader.Layout.SaltSize];
				byte[] expected_Hash, actual_Hash;
				Random r = new(42);
				r.NextBytes(key);
				r.NextBytes(expected_Salt);
				string expected_Login = "MY LOGIN йй123*%№@#!%S";
				using (var db = SecureData.DataBase.DB.Create(path, key, expected_Salt, expected_Login))
				{
					var raw = db._header.GetRawDebug();
					AssertExt.Equal(expected_Salt, DBHeader.GetSaltDebug(raw));
					Assert.Equal(expected_Login, db._header.Login);
					actual_Hash = DBHeader.GetHashDebug(raw).ToArray();
				}
				using (FileStream fs = new(path, FileMode.Open))
				{
					byte[] buffer = new byte[DBHeader.Layout.DBSize];
					fs.Read(buffer.AsSpan(0, DBHeader.Layout.EncryptionStart));
					using (BlockCryptoStream bcs = new(fs, key, expected_Salt))
					{
						bcs.Read(buffer.AsSpan(DBHeader.Layout.EncryptionStart));
					}
					using (SHA256 sha256 = new())
					{
						sha256.Transform(buffer.AsSpan(DBHeader.Layout.HashingStart));
						expected_Hash = sha256.Finalize();
					}
				}
				Assert.Equal(expected_Hash, actual_Hash);
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
