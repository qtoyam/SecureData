namespace SecureData.Storage.Exceptions
{
	public class SensitiveNotLoadedException : Exception
	{
		public SensitiveNotLoadedException() : base("Sensitive information not loaded.") { }
	}
}
