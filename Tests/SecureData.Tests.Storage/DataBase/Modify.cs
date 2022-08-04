using SecureData.Storage.Models;

namespace SecureData.Tests.Storage.DataBase
{
	public class ModifyTests : DataBaseTest
	{
		const string NewName = "brandnew name aa aa";
		const string NewDesc = "brandnew descr *(*(@*(@*(!#*(*(@#*(*(!@*(#!(*@#(**";
		const string NewLogin = "0349jasdol@mmm.com";
		const string NewPass = "*()$HJ#@)(J)(DJOPIJNMLXKNXLX";

		[Fact]
		public void Modify_Folder()
		{
			uint id;
			using (var db = Create())
			{
				FolderData data = new()
				{
					Name = Name,
					Description = Descr
				};
				db.AddData(data);
				id = data.Id;
			}
			using (var db = Init())
			{
				FolderData data = (FolderData)db.Root[0];
				db.LoadSensitive(data);
				db.ModifyData(data, x =>
				{
					x.Name = NewName;
					x.Description = NewDesc;
				});
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
			}
			using (var db = Init())
			{
				FolderData data = (FolderData)db.Root[0];
				db.LoadSensitive(data);
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
			}
		}

		[Fact]
		public void Modify_AccountData()
		{
			uint id;
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
				id = data.Id;
			}
			using (var db = Init())
			{
				AccountData data = (AccountData)db.Root[0];
				db.LoadSensitive(data);
				db.ModifyData(data, x =>
				{
					x.Name = NewName;
					x.Description = NewDesc;
					x.Login = NewLogin;
					x.Password = NewPass;
				});
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
			}
			using (var db = Init())
			{
				AccountData data = (AccountData)db.Root[0];
				db.LoadSensitive(data);
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
			}
		}

		[Fact]
		public void Modify_AccountData_NestedFolders()
		{
			const int FolderCount = 6;
			uint id;
			using (var db = Create())
			{
				FolderData? folder = null; //will be not null if nested > 0
				for (int i = 0; i < FolderCount; i++)
				{
					folder = new()
					{
						Name = Name,
						Parent = folder
					};
					db.AddData(folder);
				}
				Assert.NotNull(folder);
				AccountData data = new()
				{
					Name = Name,
					Description = Descr,
					Login = Login,
					Password = Pass,
					Parent = folder
				};
				db.AddData(data);
				id = data.Id;
				Assert.Equal(1, db.Root.Count);
			}
			using (var db = Init())
			{
				FolderData folder = (FolderData)db.Root[0];
				db.LoadSensitive(folder);
				for (int i = 1; i < FolderCount; i++) //i = 1 cauze first "folder" is root
				{
					folder = (FolderData)folder[0];
					db.LoadSensitive(folder);
				}
				Assert.NotNull(folder);
				AccountData data = (AccountData)folder[0];
				db.LoadSensitive(data);
				db.ModifyData(data, x =>
				{
					x.Name = NewName;
					x.Description = NewDesc;
					x.Login = NewLogin;
					x.Password = NewPass;
				});
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
			}
			using (var db = Init())
			{
				FolderData folder = (FolderData)db.Root[0];
				db.LoadSensitive(folder);
				for (int i = 1; i < FolderCount; i++) //i = 1 cauze first folder got above
				{
					folder = (FolderData)folder[0];
					db.LoadSensitive(folder);
				}
				Assert.NotNull(folder);
				AccountData data = (AccountData)folder[0];
				db.LoadSensitive(data);
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
			}
		}

		[Fact]
		public void Modify_AccountData_Folder()
		{
			const int FolderCount = 10;
			const string FolderNameBefore = Name + "fbef";
			const string FolderNameAfter = Name + "faft";
			uint id;
			using (var db = Create())
			{
				for (int i = 2; i < FolderCount; i++) //skip FolderBefore and FolderAfter
				{
					FolderData folder = new() { Name = Name };
					db.AddData(folder);
				}

				{
					FolderData folderAfter = new() { Name = FolderNameAfter };
					db.AddData(folderAfter);
				}
				FolderData folderBefore = new() { Name = FolderNameBefore };
				db.AddData(folderBefore);

				Assert.Equal(FolderCount, db.Root.Count);

				AccountData data = new()
				{
					Name = Name,
					Description = Descr,
					Login = Login,
					Password = Pass,
					Parent = folderBefore
				};
				db.AddData(data);
				id = data.Id;

				Assert.Equal(FolderCount, db.Root.Count);
			}
			using (var db = Init())
			{
				FolderData folderBefore = (FolderData)db.Root.Single(x => x.Name == FolderNameBefore);
				db.LoadSensitive(folderBefore);
				AccountData data = (AccountData)folderBefore[0];
				db.LoadSensitive(data);
				db.ModifyData(data, x =>
				{
					x.Name = NewName;
					x.Description = NewDesc;
					x.Login = NewLogin;
					x.Password = NewPass;
					x.Parent = (FolderData)db.Root.Single(x => x.Name == FolderNameAfter); //change Parent!
				});
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
				Assert.Same(db.Root.Single(x=>x.Name == FolderNameAfter), data.Parent);
			}
			using (var db = Init())
			{
				FolderData folderAfter = (FolderData)db.Root.Single(x => x.Name == FolderNameAfter);
				db.LoadSensitive(folderAfter);
				AccountData data = (AccountData)folderAfter[0];
				db.LoadSensitive(data);
				Assert.Equal(id, data.Id);
				Assert.Equal(NewName, data.Name);
				Assert.Equal(NewDesc, data.Description);
				Assert.Equal(NewLogin, data.Login);
				Assert.Equal(NewPass, data.Password);
				Assert.Same(db.Root.Single(x => x.Name == FolderNameAfter), data.Parent);
			}
		}
	}
}
