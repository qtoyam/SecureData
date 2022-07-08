namespace SecureData.DataBase.Exceptions
{
	public class DataBaseCorruptedException : Exception
	{
		private DataBaseCorruptedException(string reason, Exception? inner = null) :
			base($"Database is corrupted. {reason}.", inner)
		{

		}

		public static DataBaseCorruptedException WrongDBHeader() => new("Wrong database header");

		public static DataBaseCorruptedException WrongDBSize() => new("Wrong database size");
	}
}
