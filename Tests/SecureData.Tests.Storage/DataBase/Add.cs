using SecureData.Cryptography.Hash;
using SecureData.Storage.Exceptions;
using SecureData.Storage.Models;

namespace SecureData.Tests.Storage.DataBase
{
	public class AddTests : DataBaseTest
	{
		[Fact]
		public void AddFolder()
		{
			uint exp_Id;
			byte[] exp_Hash;
			long exp_DataType;
			using (var db = Create())
			{
				FolderData folder = new()
				{
					Name = Name,
					Description = Descr
				};
				db.AddData(folder);
				Assert.Equal(1, db.Root.Count);
				Assert.True(ReferenceEquals(folder, db.Root[0]));
				exp_Id = folder.Id;
				exp_Hash = folder.Hash.ToArray();
				exp_DataType = folder.DataType;
			}
			using (var db = Init())
			{
				Assert.Equal(1, db.Root.Count);
				FolderData folder = (FolderData)db.Root[0];
				Assert.Equal(Name, folder.Name);
				Assert.Equal(Descr, folder.Description);
				Assert.Equal(exp_Id, folder.Id);
				Assert.Equal(exp_Hash, folder.Hash.ToArray());
				Assert.Equal(exp_DataType, folder.DataType);
			}
		}

		[Fact]
		public void AddAccountData()
		{
			uint exp_Id;
			byte[] exp_Hash;
			long exp_DataType;
			using (var db = Create())
			{
				AccountData data = new()
				{
					Name = Name,
					Description = Descr,
					Login = Login,
					Password = Pass
				};
				db.AddData(data);
				Assert.Equal(1, db.Root.Count);
				Assert.Same(data, db.Root[0]);
				exp_Id = data.Id;
				exp_Hash = data.Hash.ToArray();
				exp_DataType = data.DataType;
			}
			using (var db = Init())
			{
				Assert.Equal(1, db.Root.Count);
				AccountData data = (AccountData)db.Root[0];
				Assert.Equal(Name, data.Name);
				Assert.Equal(Descr, data.Description);
				Assert.Equal(exp_Id, data.Id);
				Assert.Equal(exp_Hash, data.Hash.ToArray());
				Assert.Equal(exp_DataType, data.DataType);

				Assert.Throws<DataLoadedException>(() => data.Login);
				Assert.Throws<DataLoadedException>(() => data.Password);

				db.LoadSensitive(data);
				Assert.Equal(Login, data.Login);
				Assert.Equal(Pass, data.Password);
			}
		}

		[Fact]
		public void AddAccountData_100()
		{
			const int dataCount = 100;
			using (var db = Create())
			{
				for (int i = 0; i < dataCount; i++)
				{
					string istr = i.ToString();
					AccountData data = new()
					{
						Name = Name + istr,
						Description = istr,
						Login = Login + istr,
						Password = Pass + istr
					};
					db.AddData(data);
					Assert.Equal(i + 1, db.Root.Count);
				}
			}
			using (var db = Init())
			{
				Assert.Equal(dataCount, db.Root.Count);
				for (int i = 0; i < dataCount; i++)
				{
					AccountData data = (AccountData)db.Root[i];
					string istr = data.Description;
					Assert.Equal(Name + istr, data.Name);

					Assert.Throws<DataLoadedException>(() => data.Login);
					Assert.Throws<DataLoadedException>(() => data.Password);

					db.LoadSensitive(data);
					Assert.Equal(Login + istr, data.Login);
					Assert.Equal(Pass + istr, data.Password);
				}
			}
		}

		[Fact]
		public void AddAccountData_WithParent()
		{
			const string NameFolder = Name + "Folder213#й";
			const string DescrFolder = Descr + "daspo12234джьлФЫВss#$%^";
			uint data_Id;
			byte[] data_Hash;
			long data_DataType;
			using (var db = Create())
			{
				FolderData folder = new()
				{
					Name = NameFolder,
					Description = DescrFolder
				};
				db.AddData(folder);
				Assert.Equal(1, db.Root.Count);
				Assert.Same(folder, db.Root[0]);
				AccountData data = new()
				{
					Name = Name,
					Description = Descr,
					Login = Login,
					Password = Pass,
					Parent = folder
				};
				db.AddData(data);
				Assert.Equal(1, db.Root.Count);
				data_Id = data.Id;
				data_Hash = data.Hash.ToArray();
				data_DataType = data.DataType;
			}
			using (var db = Init())
			{
				Assert.Equal(1, db.Root.Count);

				FolderData folder = (FolderData)db.Root[0];
				Assert.Equal(NameFolder, folder.Name);
				Assert.Equal(DescrFolder, folder.Description);

				AccountData data = (AccountData)folder[0];
				Assert.Equal(Name, data.Name);
				Assert.Equal(Descr, data.Description);
				Assert.Equal(data_Id, data.Id);
				Assert.Equal(data_Hash, data.Hash.ToArray());
				Assert.Equal(data_DataType, data.DataType);

				Assert.Throws<DataLoadedException>(() => data.Login);
				Assert.Throws<DataLoadedException>(() => data.Password);

				db.LoadSensitive(data);
				Assert.Equal(Login, data.Login);
				Assert.Equal(Pass, data.Password);
			}
		}

		[Fact]
		public void AddDuplicate()
		{
			using (var db = Create())
			{
				AccountData data = new()
				{
					Name = Name,
					Description = Descr,
					Login = Login,
					Password = Pass
				};
				db.AddData(data);
				Assert.Throws<UnexpectedException>(
					() => db.AddData(data));
			}
		}
	}
}
