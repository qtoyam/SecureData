using System.Text;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models;

namespace SecureData.Tests.DataBase.DB
{
	public class InitTests
	{
		[Fact]
		public void Init_NoData()
		{
			string path = $"{nameof(Init_NoData)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				Span<byte> key = new byte[AesCtr.KeySize];
				Span<byte> data = new byte[DBHeader.Layout.RNGSize + DBHeader.Size];
				Span<byte> salt = data.Slice(DBHeader.Layout.SaltOffset, DBHeader.Layout.SaltSize);
				Span<byte> hash = data.Slice(DBHeader.Layout.HashOffset, DBHeader.Layout.HashSize);
				Span<byte> rng = data.Slice(DBHeader.Layout.RNGOffset, DBHeader.Layout.RNGSize);
				string login = "MY LOGINn12377842189&^#&^@!89sa;as\"" + '\0'; //null terminate cauze we emulate creation of file
				uint version = 1;
				RNG(key, data);
				BinaryHelper.Write(data.Slice(DBHeader.Layout.VersionOffset), version);
				BinaryHelper.Write(data.Slice(DBHeader.Layout.LoginOffset, DBHeader.Layout.LoginSize), Encoding.UTF8.GetBytes(login));
				SHA256.ComputeHash(data.Slice(DBHeader.HashStart), hash);
				using (var bcs = new BlockCryptoStream(path,
					new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create }, key, salt))
				{
					bcs.WriteThroughEncryption(data.Slice(0, DBHeader.Layout.RNGOffset));
					bcs.Write(data.Slice(DBHeader.Layout.RNGOffset));
				}
				using (var db = new SecureData.DataBase.DB(path))
				{
					bool res = db.TryInit(key);
					Assert.True(res);
					Assert.Equal(login[..^1], db.Login);
					Assert.Equal(version, db.Version);
					AssertExt.Equal(salt, db.Salt);
					AssertExt.Equal(hash, db.Hash);
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

		[Fact]
		public void Init_WrongKey()
		{
			string path = $"{nameof(Init_WrongKey)}TMP0.tmp";
			DeleteFile(path);
			try
			{
				Span<byte> key = new byte[AesCtr.KeySize];
				Span<byte> data = new byte[DBHeader.Layout.RNGSize + DBHeader.Size];
				Span<byte> salt = data.Slice(DBHeader.Layout.SaltOffset, DBHeader.Layout.SaltSize);
				Span<byte> hash = data.Slice(DBHeader.Layout.HashOffset, DBHeader.Layout.HashSize);
				Span<byte> rng = data.Slice(DBHeader.Layout.RNGOffset, DBHeader.Layout.RNGSize);
				string login = "MY LOGINn12377842189&^#&^@!89sa;as\"" + '\0';
				uint version = 1;
				RNG(key, data);
				BinaryHelper.Write(data.Slice(DBHeader.Layout.VersionOffset), version);
				BinaryHelper.Write(data.Slice(DBHeader.Layout.LoginOffset, DBHeader.Layout.LoginSize), Encoding.UTF8.GetBytes(login));
				SHA256.ComputeHash(data.Slice(DBHeader.HashStart), hash);
				using (var bcs = new BlockCryptoStream(path,
					new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create }, key, salt))
				{
					bcs.WriteThroughEncryption(data.Slice(0, DBHeader.Layout.RNGOffset));
					bcs.Write(data.Slice(DBHeader.Layout.RNGOffset));
				}
				using (var db = new SecureData.DataBase.DB(path))
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
				DeleteFile(path);
			}
		}
	}
}
