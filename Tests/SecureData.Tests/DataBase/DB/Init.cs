using System.Text;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Helpers;

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
				Span<byte> key = new byte[Aes.KeySize];
				Span<byte> data = new byte[Sizes.DBSize];
				Span<byte> salt = data.Slice(Sizes.SaltOffset, Sizes.SaltSize);
				Span<byte> hash = data.Slice(Sizes.HashOffset, Sizes.HashSize);
				Span<byte> rng = data.Slice(Sizes.RNGOffset, Sizes.RNGSize);
				string login = "MY LOGINn12377842189&^#&^@!89sa;as\"" + '\0'; //null terminate cauze we emulate creation of file
				uint version = 1;
				RNG(key, data);
				BinaryHelper.Write(data.Slice(Sizes.VersionOffset), version);
				BinaryHelper.Write(data.Slice(Sizes.LoginOffset, Sizes.LoginSize), Encoding.UTF8.GetBytes(login));
				SHA256.ComputeHash(data.Slice(Sizes.HashStart), hash);
				using (var bcs = new BlockCryptoStream(path,
					new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.CreateNew }, key, salt))
				{
					bcs.WriteThroughEncryption(data.Slice(0, Sizes.SelfEncryptStart));
					bcs.Write(data.Slice(Sizes.SelfEncryptStart));
				}
				using (var db = new SecureData.DataBase.DB(path, false))
				{
					bool res = db.TryInit(key);
					Assert.True(res);
					Assert.Equal(login[..^1], db.Login);
					Assert.Equal(version, db.Version);
					AssertExt.Equal(salt, db.Salt.Span);
					AssertExt.Equal(hash, db.Hash.Span);
				}
			}
			catch (Exception ex)
			{
				throw new Exception($"Seed: {Seed}", ex);
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
		public void Init_WrongKey()
		{
			string path = $"{nameof(Init_WrongKey)}TMP0.tmp";
			try
			{
				Span<byte> key = new byte[Aes.KeySize];
				Span<byte> data = new byte[Sizes.DBSize];
				Span<byte> salt = data.Slice(Sizes.SaltOffset, Sizes.SaltSize);
				Span<byte> hash = data.Slice(Sizes.HashOffset, Sizes.HashSize);
				Span<byte> rng = data.Slice(Sizes.RNGOffset, Sizes.RNGSize);
				string login = "MY LOGINn12377842189&^#&^@!89sa;as\"" + '\0';
				uint version = 1;
				RNG(key, data);
				BinaryHelper.Write(data.Slice(Sizes.VersionOffset), version);
				BinaryHelper.Write(data.Slice(Sizes.LoginOffset, Sizes.LoginSize), Encoding.UTF8.GetBytes(login));
				SHA256.ComputeHash(data.Slice(Sizes.HashStart), hash);
				using (var bcs = new BlockCryptoStream(path,
					new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.CreateNew }, key, salt))
				{
					bcs.WriteThroughEncryption(data.Slice(0, Sizes.SelfEncryptStart));
					bcs.Write(data.Slice(Sizes.SelfEncryptStart));
				}
				using (var db = new SecureData.DataBase.DB(path, false))
				{
					key[1]++; //modify key
					bool res = db.TryInit(key);
					Assert.False(res);
				}
			}
			catch (Exception ex)
			{
				throw new Exception($"Seed: {Seed}", ex);
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
