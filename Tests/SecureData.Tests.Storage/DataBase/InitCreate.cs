using SecureData.Cryptography.Hash;
using SecureData.Storage.Exceptions;

namespace SecureData.Tests.Storage.DataBase
{
	public class InitCreateTests : DataBaseTest
	{
		[Fact]
		public void CreateEmpty()
		{
			using (var db = Create())
			{
			}
		}

		[Fact]
		public void CreateInit_Empty()
		{
			using (var db = Create())
			{
			}
			using (var db = Init())
			{
				Assert.Equal(0, db.Root.Count);
			}
		}

		[Fact]
		public void CreateInit_WrongPassword()
		{
			string path;
			using (var db = Create2(out path))
			{
			}
			using (var db = new SecureData.Storage.DataBase(path))
			{
				bool created = db.TryInit(DBPass + "0");
				Assert.False(created, "Database created with wrong key!");
			}
		}

		[Fact]
		public void CreateInit_10Attemps()
		{
			const int attemps = 10;
			string path;
			using (var db = Create2(out path))
			{
			}
			using (var db = new SecureData.Storage.DataBase(path))
			{
				bool created;
				for (int i = 0; i < attemps; i++)
				{
					created = db.TryInit($"{DBPass}{i}");
					Assert.False(created);
				}
				created = db.TryInit(DBPass);
				Assert.True(created);
				Assert.Equal(0, db.Root.Count);
				Assert.Equal(DBLogin, db.Login);
			}
		}

		[Fact]
		public void CreateInit_ChangedFile()
		{
			string path;
			using (var db = Create2(out path))
			{
			}
			using (var fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite))
			{
				fs.Position = fs.Length - 1;
				byte fs_byte = Convert.ToByte(fs.ReadByte());
				fs_byte++;
				fs.Position--;
				fs.WriteByte(fs_byte);
			}
			using (var db = new SecureData.Storage.DataBase(path))
			{
				bool created = db.TryInit(DBPass);
				Assert.False(created);
			}
		}

		[Fact]
		public void CreateInit_LengthTruncated()
		{
			string path;
			using (var db = Create2(out path))
			{
			}
			using (var fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite))
			{
				fs.SetLength(fs.Length - 1);
			}
			using (var db = new SecureData.Storage.DataBase(path))
			{
				Assert.Throws<DataBaseCorruptedException>(
					() =>
					{
						db.TryInit(DBPass);
					});
			}
		}

		[Fact]
		public void CreateInit_LengthAdded()
		{
			string path;
			using (var db = Create2(out path))
			{
			}
			using (var fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite))
			{
				fs.SetLength(fs.Length + Cryptography.SymmetricEncryption.AesCtr.BlockSize);
			}
			using (var db = new SecureData.Storage.DataBase(path))
			{
				//TODO: check in try init can file length be real (check combos -> header size + any number of items of any type)
				//Assert.Throws<DataBaseCorruptedException>(
				//	() =>
				//	{
				//		db.TryInit(DBPass);
				//	});
				bool created = db.TryInit(DBPass);
				Assert.False(created);
			}
		}
	}
}
