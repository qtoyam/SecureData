namespace SecureData.DataBase.Models
{
	[Flags]
	public enum DataType : uint
	{
		AccountData = 1U<<0,
		DataFolder = 1U<<1,
		Deleted = 1U << 31,
	}
}
