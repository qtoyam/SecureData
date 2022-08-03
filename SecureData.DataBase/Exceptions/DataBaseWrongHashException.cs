namespace SecureData.Storage.Exceptions
{
	public class DataBaseWrongHashException : Exception
	{
		public DataBaseWrongHashException() : base("Database has wrong hash value.")
		{

		}
	}
}
