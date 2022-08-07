using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Storage.Exceptions;
using SecureData.Storage.Models;

namespace SecureData.Tests.Storage.DataBase
{
	public class DeleteTests : DataBaseTest
	{
		[Fact]
		public void Remove_AccounData_Last()
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
				Assert.Equal(1, db.Root.Count);
				db.DeleteData(data);
				Assert.Equal(0, db.Root.Count);
			}
			using (var db = Init())
			{
				Assert.Equal(0, db.Root.Count);
			}
		}

		[Fact]
		public void Remove_FolderData_WithChilds()
		{
			const int dataCount = 100;
			using (var db = Create())
			{
				FolderData folder = new() { Name = Name };
				db.AddData(folder);
				for (int i = 0; i < dataCount; i++)
				{
					string istr = i.ToString();
					AccountData data = new()
					{
						Name = Name + istr,
						Description = istr,
						Login = Login + istr,
						Password = Pass + istr,
						Parent = folder
					};
					db.AddData(data);
					Assert.Equal(1, db.Root.Count);
				}
			}
			using (var db = Init())
			{
				Assert.Equal(1, db.Root.Count);
				db.DeleteData(db.Root[0]);
				Assert.Equal(0, db.Root.Count);
			}
			using (var db = Init())
			{
				Assert.Equal(0, db.Root.Count);
			}
		}

		[Fact]
		public void Remove_FolderData_WithChilds_2()
		{
			const int dataCount = 11;
			const int extraItems = 30;
			uint idToDel = 0;
			using (var db = Create())
			{
				FolderData folder = new() { Name = Name };
				db.AddData(folder);
				idToDel = folder.Id;
				for (int i = 0; i < dataCount; i++)
				{
					string istr = i.ToString();
					AccountData data = new()
					{
						Name = Name + istr,
						Description = istr,
						Login = Login + istr,
						Password = Pass + istr,
						Parent = folder
					};
					db.AddData(data);
					Assert.Equal(1, db.Root.Count);
				}
				for (int i = 1; i <= extraItems; i++)
				{
					AccountData data = new() { Name = Name };
					db.AddData(data);
					Assert.Equal(i + 1, db.Root.Count);
				}
			}
			using (var db = Init())
			{
				Assert.Equal(1 + extraItems, db.Root.Count);
				db.DeleteData(db.Root.Single(x=>x.Id == idToDel));
				Assert.Equal(extraItems, db.Root.Count);
			}
			using (var db = Init())
			{
				Assert.Equal(extraItems, db.Root.Count);
			}
		}
	}
}
