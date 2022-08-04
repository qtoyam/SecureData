namespace SecureData.Storage.Exceptions
{
	public class DataLoadedException : Exception
	{
		public DataLoadedException(bool shouldBeLoaded) : base(shouldBeLoaded ? "Data is unloaded." : "Data is loaded.") { }
	}
}
