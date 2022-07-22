using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class AddDataTests
	{
		[Fact]
		public void AddData_NoLock_EmptyDB()
		{
			string path = $"{nameof(AddData_NoLock_EmptyDB)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				byte[] db_key = new byte[Aes.KeySize];
				byte[] db_iv = new byte[Aes.IVSize];
				RNG(db_key, db_iv);
				byte[] exp_DB_Hash, act_DB_Hash;
				long exp_Length, act_Length;
				string exp_Name, exp_Descr, exp_Login, exp_Pass;
				uint exp_Id, exp_DataType;
				byte[] exp_Hash, exp_Salt;
				DateTime exp_TimeStamp, exp_LastEdit;
				bool exp_IsEncrypted;
				exp_Name = "acc data naame";
				exp_Descr = "acc descr val";
				exp_Login = "qto@mail.eu";
				exp_Pass = "zxc123ZXC";
				using (var db = new SecureData.DataBase.DB(path, true))
				{
					db.Create(db_key, db_iv, "my login");
					AccountData accountData = new AccountData
					{
						Name = exp_Name,
						Description = exp_Descr,
						Login = exp_Login,
						Password = exp_Pass
					};
					db.AddData(accountData);
					exp_Id = accountData.Id;
					exp_DataType = accountData.DataType;
					exp_Hash = accountData.Hash.ToArray();
					exp_IsEncrypted = accountData.IsEncrypted;
					exp_Salt = accountData.Salt.ToArray();
					exp_TimeStamp = accountData.TimeStamp;
					exp_LastEdit = accountData.LastEdit;
					act_DB_Hash = db.Hash.ToArray();
					exp_Length = Sizes.DBSize + accountData.Size;
				}
				using (var bcs = new BlockCryptoStream(path,
					  new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open }, db_key, db_iv))
				{
					byte[] buffer = new byte[bcs.Length];
					bcs.ReadThroughEncryption(buffer.AsSpan(0, Sizes.Size));
					bcs.Read(buffer.AsSpan(Sizes.Size));
					exp_DB_Hash = SHA256.ComputeHash(buffer.AsSpan(Sizes.HashStart));
					act_Length = bcs.Length;
				}
				Assert.Equal(exp_DB_Hash, act_DB_Hash);
				Assert.Equal(exp_Length, act_Length);
				using (var db = new SecureData.DataBase.DB(path, false))
				{
					bool res = db.TryInit(db_key);
					Assert.True(res);
					Assert.True(db.Root.Count == 1);
					AccountData ad = (AccountData)db.Root[0];
					Assert.Equal(exp_Id, ad.Id);
					Assert.Equal(exp_DataType, ad.DataType);
					AssertExt.Equal(exp_Hash, ad.Hash);
					Assert.Equal(exp_IsEncrypted, ad.IsEncrypted);
					AssertExt.Equal(exp_Salt, ad.Salt);
					Assert.Equal(exp_TimeStamp, ad.TimeStamp);
					Assert.Equal(exp_LastEdit, ad.LastEdit);

					Assert.Equal(exp_Name, ad.Name);
					Assert.Equal(exp_Descr, ad.Description);

					Assert.Equal(exp_Login, ad.Login);
					Assert.Equal(exp_Pass, ad.Password);
				}
			}
			finally
			{
				DeleteFile(path);
			}
		}

		[Fact]
		public void AddData_Lock_EmptyDB()
		{
			string path = $"{nameof(AddData_Lock_EmptyDB)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				byte[] db_key = new byte[Aes.KeySize];
				byte[] db_iv = new byte[Aes.IVSize];
				byte[] data_key = new byte[Aes.KeySize];
				RNG(db_key, db_iv, data_key);
				byte[] exp_DB_Hash, act_DB_Hash;
				long exp_Length, act_Length;
				string exp_Name, exp_Descr, exp_Login, exp_Pass;
				uint exp_Id, exp_DataType;
				byte[] exp_Hash, exp_Salt;
				DateTime exp_TimeStamp, exp_LastEdit;
				bool exp_IsEncrypted;
				exp_Name = "acc data naame";
				exp_Descr = "acc descr val";
				exp_Login = "qto@mail.eu";
				exp_Pass = "zxc123ZXC";
				using (var db = new SecureData.DataBase.DB(path, true))
				{
					db.Create(db_key, db_iv, "my login");
					AccountData accountData = new AccountData
					{
						Name = exp_Name,
						Description = exp_Descr,
						Login = exp_Login,
						Password = exp_Pass
					};
					accountData.MakeEncrypted(data_key);
					db.AddData(accountData);
					exp_Id = accountData.Id;
					exp_DataType = accountData.DataType;
					exp_Hash = accountData.Hash.ToArray();
					exp_IsEncrypted = accountData.IsEncrypted;
					exp_Salt = accountData.Salt.ToArray();
					exp_TimeStamp = accountData.TimeStamp;
					exp_LastEdit = accountData.LastEdit;
					act_DB_Hash = db.Hash.ToArray();
					exp_Length = Sizes.DBSize + accountData.Size;
				}
				using (var bcs = new BlockCryptoStream(path,
					  new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open }, db_key, db_iv))
				{
					byte[] buffer = new byte[bcs.Length];
					bcs.ReadThroughEncryption(buffer.AsSpan(0, Sizes.Size));
					bcs.Read(buffer.AsSpan(Sizes.Size));
					exp_DB_Hash = SHA256.ComputeHash(buffer.AsSpan(Sizes.HashStart));
					act_Length = bcs.Length;
				}
				Assert.Equal(exp_DB_Hash, act_DB_Hash);
				Assert.Equal(exp_Length, act_Length);
				using (var db = new SecureData.DataBase.DB(path, false))
				{
					bool res = db.TryInit(db_key);
					Assert.True(res);
					Assert.True(db.Root.Count == 1);
					AccountData ad = (AccountData)db.Root[0];
					Assert.Equal(exp_Id, ad.Id);
					Assert.Equal(exp_DataType, ad.DataType);
					AssertExt.Equal(exp_Hash, ad.Hash);
					Assert.Equal(exp_IsEncrypted, ad.IsEncrypted);
					AssertExt.Equal(exp_Salt, ad.Salt);
					Assert.Equal(exp_TimeStamp, ad.TimeStamp);
					Assert.Equal(exp_LastEdit, ad.LastEdit);

					Assert.Equal(exp_Name, ad.Name);
					Assert.Equal(exp_Descr, ad.Description);

					Assert.Throws<InvalidOperationException>(() => ad.Login); //try get sens info without unlock

					bool res_Unlock;
					res_Unlock = ad.TryUnlock(db_key);
					Assert.False(res_Unlock);

					res_Unlock = ad.TryUnlock(data_key);
					Assert.True(res_Unlock);

					Assert.Equal(exp_Login, ad.Login);
					Assert.Equal(exp_Pass, ad.Password);
				}
			}
			finally
			{
				DeleteFile(path);
			}
		}

		[Fact]
		public void AddFolder_EmptyDB()
		{
			string path = $"{nameof(AddFolder_EmptyDB)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				byte[] db_key = new byte[Aes.KeySize];
				byte[] db_iv = new byte[Aes.IVSize];
				byte[] data_key = new byte[Aes.KeySize];
				RNG(db_key, db_iv, data_key);
				byte[] exp_DB_Hash, act_DB_Hash;
				long exp_Length, act_Length;
				string exp_Name, exp_Descr;
				uint exp_Id, exp_DataType;
				byte[] exp_Hash, exp_Salt;
				DateTime exp_TimeStamp, exp_LastEdit;
				bool exp_IsEncrypted;
				exp_Name = "acc data naame";
				exp_Descr = "acc descr val";
				using (var db = new SecureData.DataBase.DB(path, true))
				{
					db.Create(db_key, db_iv, "my login");
					FolderData folder = new FolderData()
					{
						Name = exp_Name,
						Description = exp_Descr
					};
					folder.MakeEncrypted(data_key);
					db.AddData(folder);
					exp_Id = folder.Id;
					exp_DataType = folder.DataType;
					exp_Hash = folder.Hash.ToArray();
					exp_IsEncrypted = folder.IsEncrypted;
					exp_Salt = folder.Salt.ToArray();
					exp_TimeStamp = folder.TimeStamp;
					exp_LastEdit = folder.LastEdit;
					act_DB_Hash = db.Hash.ToArray();
					exp_Length = Sizes.DBSize + folder.Size;
				}
				using (var bcs = new BlockCryptoStream(path,
					  new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open }, db_key, db_iv))
				{
					byte[] buffer = new byte[bcs.Length];
					bcs.ReadThroughEncryption(buffer.AsSpan(0, Sizes.Size));
					bcs.Read(buffer.AsSpan(Sizes.Size));
					exp_DB_Hash = SHA256.ComputeHash(buffer.AsSpan(Sizes.HashStart));
					act_Length = bcs.Length;
				}
				Assert.Equal(exp_DB_Hash, act_DB_Hash);
				Assert.Equal(exp_Length, act_Length);
				using (var db = new SecureData.DataBase.DB(path, false))
				{
					bool res = db.TryInit(db_key);
					Assert.True(res);
					Assert.True(db.Root.Count == 1);
					FolderData folder = (FolderData)db.Root[0];
					Assert.Equal(exp_Id, folder.Id);
					Assert.Equal(exp_DataType, folder.DataType);
					AssertExt.Equal(exp_Hash, folder.Hash);
					Assert.Equal(exp_IsEncrypted, folder.IsEncrypted);
					AssertExt.Equal(exp_Salt, folder.Salt);
					Assert.Equal(exp_TimeStamp, folder.TimeStamp);
					Assert.Equal(exp_LastEdit, folder.LastEdit);

					Assert.Equal(exp_Name, folder.Name);
					Assert.Equal(exp_Descr, folder.Description);
				}
			}
			finally
			{
				DeleteFile(path);
			}
		}
	}
}
