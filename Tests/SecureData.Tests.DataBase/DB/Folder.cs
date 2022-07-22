using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class FolderTests
	{
		[Fact]
		public void AddData_1Folder()
		{
			string path = $"{nameof(AddData_1Folder)}TMP0.tmp";
			const int accounts_count = 50;
			DeleteFile(path);
			try
			{
				byte[] db_key = new byte[Aes.KeySize];
				byte[] db_iv = new byte[Aes.IVSize];
				byte[] folder_key = new byte[Aes.KeySize];
				RNG(db_key, db_iv, folder_key);
				byte[] exp_DB_Hash, act_DB_Hash;
				long exp_Length, act_Length;
				string exp_Name, exp_Description, exp_Login, exp_Password;
				exp_Name = "some name123ASD!@#";
				exp_Description = "som DSCRR@*)()(S";
				exp_Login = "test@email.com.something";
				exp_Password = "9uh9iH(AS*9823hlasdSAQWE";
				using (var db = new SecureData.DataBase.DB(path, true))
				{
					exp_Length = Sizes.DBSize;
					db.Create(db_key, db_iv, "my login");
					{
						FolderData f = new FolderData()
						{
							Name = "my folder1",
							Description = "my folder descr1"
						};
						f.MakeEncrypted(folder_key);
						db.AddData(f);
					}
					Assert.Equal(1, db.Root.Count);
					FolderData folder = (FolderData)db.Root[0];

					for (int i = 0; i < accounts_count; i++)
					{
						AccountData acc = new AccountData()
						{
							Name = exp_Name,
							Description = exp_Description,
							Login = exp_Login,
							Password = exp_Password
						};
						folder.AddChild(acc);
						db.AddData(acc);
						exp_Length += acc.Size;
					}
					Assert.Equal(1, db.Root.Count);

					act_DB_Hash = db.Hash.ToArray();
					exp_Length += folder.Size;
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
					Assert.Equal(1, db.Root.Count);
					FolderData folder = (FolderData)db.Root[0];
					Assert.Equal(accounts_count, folder.Childs.Count);

					foreach (var d in folder.Childs.Values)
					{
						AccountData acc = (AccountData)d;
						Assert.Throws<InvalidOperationException>(() => acc.Name);
					}
					bool res_UnlockFolder;
					res_UnlockFolder = folder.TryUnlock(db_key);
					Assert.False(res_UnlockFolder);
					res_UnlockFolder = folder.TryUnlock(folder_key);
					Assert.True(res_UnlockFolder);
					foreach (var d in folder.Childs.Values)
					{
						AccountData acc = (AccountData)d;
						Assert.Equal(exp_Name, acc.Name);
						Assert.Equal(exp_Description, acc.Description);
						Assert.Equal(exp_Login, acc.Login);
						Assert.Equal(exp_Password, acc.Password);
					}
				}
			}
			finally
			{
				DeleteFile(path);
			}
		}
	}
}
