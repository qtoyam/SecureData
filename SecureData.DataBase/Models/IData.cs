namespace SecureData.DataBase.Models
{
	public interface IData
	{
		public static class Layout
		{
			//TODO: here
		}
		public DataType DataType { get; }
		public UInt32 Id { get; }
		public IData? Parent { get; }
		public DateTime TimeStamp { get; }
	}
}
