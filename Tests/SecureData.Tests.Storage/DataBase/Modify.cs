using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using SecureData.Cryptography.Hash;
using SecureData.Cryptography.SymmetricEncryption;

using SecureData.Storage.Models;

namespace SecureData.Tests.Storage.DataBase
{
	public class ModifyTests : DataBaseTest
	{
		[Fact]
		public void Modify_Directly()
		{
			//string path = GetPath();
			//using (DB database = new DB(path))
			//{
			//	database.Create(DBLogin, DBPass, ArgonOptions);
			//	Assert.Equal(DBLogin, database.Login);
			//	Assert.Equal(0, database.Root.Count);
			//	AccountData data = new()
			//	{
			//		Name = Name,
			//		Description = Descr,
			//		Login = Login,
			//		Password = Pass
			//	};
			//	database.AddData(data);
			//	Assert.Throws<InvalidOperationException>(
			//		() => database.AddData(data));
			//}
		}
	}
}
