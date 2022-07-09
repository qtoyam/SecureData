using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class InitAndCreateTests
	{
		[Fact]
		public void InitAndCreate_NoData()
		{
			string path = $"{nameof(InitAndCreate_NoData)}TMP0.tmp";
			try
			{
				byte[] key = new byte[Aes256Ctr.KeySize];
				byte[] expected_Salt = new byte[DBHeader.Layout.SaltSize];
				Random r = new(42);
				r.NextBytes(key);
				r.NextBytes(expected_Salt);
				string expected_Login = "MY LOGIN йй123*%№@#!%S";
				using (var db = SecureData.DataBase.DB.Create(path, key, expected_Salt, expected_Login))
				{

				}
				using (var db = SecureData.DataBase.DB.Init(path, key))
				{
					var raw = db._header.GetRawDebug();
					AssertExt.Equal(expected_Salt, DBHeader.GetSaltDebug(raw)); //salt
					Assert.Equal(expected_Login, db._header.Login);
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
	}
}
