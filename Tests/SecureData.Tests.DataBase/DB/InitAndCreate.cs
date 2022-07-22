using SecureData.Cryptography.SymmetricEncryption;

namespace SecureData.Tests.DataBase.DB
{
	public class InitAndCreateTests
	{
		[Fact]
		public void InitAndCreate_NoData()
		{
			string path = $"{nameof(InitAndCreate_NoData)}TMP0.tmp";
			DeleteFile(path);
			Span<byte> key = new byte[Aes.KeySize];
			Span<byte> iv = new byte[Aes.IVSize];
			string login = "MY LOGINn12377842189&^#&^@!89sa;as\"";
			byte[] exp_hash, act_hash;
			byte[] exp_salt, act_salt;
			uint exp_version, act_version;
			RNG(key, iv);
			try
			{
				using(var db = new SecureData.DataBase.DB(path, true))
				{
					db.Create(key, iv,login);
					exp_hash = db.Hash.ToArray();
					exp_salt = db.Salt.ToArray();
					exp_version = db.Version;
				}
				using(var db = new SecureData.DataBase.DB(path, false))
				{
					bool res = db.TryInit(key);
					Assert.True(res);
					Assert.Equal(login, db.Login);
					act_hash = db.Hash.ToArray();
					Assert.Equal(exp_hash, act_hash);
					act_salt = db.Salt.ToArray();
					Assert.Equal(exp_salt, act_salt);
					act_version = db.Version;
					Assert.Equal(exp_version, act_version);

				}
			}
			catch (Exception ex)
			{
				throw new Exception($"Seed: {Seed}", ex);
			}
			finally
			{
				DeleteFile(path);
			}
		}
	}
}
