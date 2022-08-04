using System.Runtime.CompilerServices;

using SecureData.Cryptography.Hash;

using DB = SecureData.Storage.DataBase;

namespace SecureData.Tests.Storage.DataBase
{
	//TODO:9 name, descr etc pseudorandom string
	public abstract class DataBaseTest : IDisposable
	{
		public const string DBLogin = "my login hihia@#!()@#()c";
		public const string DBPass = "my pass xXx213(DS";
		public const string Name = "data my name";
		public const string Descr = "data my decriptuionasd o234902390nasdo ";
		public const string Login = "iasdinkil@dkopas...x...x..";
		public const string Pass = "my a[23478309u_I#$)_$_#@sxxЙЦУ";
		private readonly Argon2dOptions ArgonOptions = new(1, 64 * 1024, 1);

		private readonly HashSet<string> _createdDBs = new(); 

		public DB Create([CallerMemberName] string caller = "")
		{
			return Create2(out _, caller);
		}

		public DB Create2(out string path,[CallerMemberName] string caller = "")
		{
			DB? database = null;
			path = caller + ".TTMP";
			if (!_createdDBs.Add(path))
			{
				throw new InvalidOperationException("Db already created.");
			}
			if (File.Exists(path))
			{
				File.Delete(path);
			}
			try
			{
				database = new DB(path);
				database.Create(DBLogin, DBPass, ArgonOptions);
				Assert.Equal(DBLogin, database.Login);
				Assert.Empty(database.Root);
				return database;
			}
			catch
			{
				database?.Dispose();
				throw;
			}
		}


		public DB Init([CallerMemberName] string caller = "")
		{
			DB? database = null;
			string path = caller + ".TTMP";
			if(!_createdDBs.Contains(path))
			{
				throw new InvalidOperationException("DB not created.");
			}
			try
			{
				database = new DB(path);
				bool res = database.TryInit(DBPass);
				Assert.True(res, "Database not inited");
				Assert.Equal(DBLogin, database.Login);
				return database;
			}
			catch
			{
				database?.Dispose();
				throw;
			}
		}
		public void Dispose()
		{
			foreach (var dbPath in _createdDBs.Where(x=> File.Exists(x)))
			{
				File.Delete(dbPath);
			}
			GC.SuppressFinalize(this);
		}
	}
}
