using SecureData.Storage.Models.Abstract;

namespace SecureData.Storage.Exceptions
{
	public class DataWrongHashException : Exception
	{
		public DataWrongHashException(Data data) : base($"Data wrong hash, id = {data.Id}") { }
	}
}
