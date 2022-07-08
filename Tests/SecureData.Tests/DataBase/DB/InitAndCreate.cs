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
		public async Task InitAndCreate_NoData()
		{
			string path = $"{nameof(InitAndCreate_NoData)}TMP0.tmp";
			try
			{
				byte[] key = new byte[Aes256Ctr.KeySize];
				byte[] expected_Salt = new byte[DBHeader.Layout.SaltSize];
				string expected_Login = "MY LOGIN йй123*%№@#!%S";
				using (var db = await SecureData.DataBase.DB.CreateAsync(path, key, expected_Salt, expected_Login))
				{

				}
				using (var db = await SecureData.DataBase.DB.InitAsync(path, key))
				{
					AssertExt.Equal(expected_Salt, db._header.Salt);
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
