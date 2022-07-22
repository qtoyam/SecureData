namespace SecureData.DataBase.Exceptions
{
	public class DataBaseCorruptedException : Exception
	{
		private DataBaseCorruptedException(string reason, Exception? inner = null) :
			base($"Database is corrupted. {reason}.", inner)
		{

		}

		public static DataBaseCorruptedException WrongDBHeader() => new("Wrong database header.");

		public static DataBaseCorruptedException WrongDBSize() => new("Wrong database size.");

		public static DataBaseCorruptedException WrongDataItemsSize() => new("Data items corrupted, not enough size bytes.");

		public static DataBaseCorruptedException UnexpectedHash() => new("Unexpected wrong hash value.");
	}
}
