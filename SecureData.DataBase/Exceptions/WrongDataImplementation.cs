namespace SecureData.DataBase.Exceptions
{
	public class WrongDataImplementation : Exception
	{
		public WrongDataImplementation(Type implType, string wrongImplementedName)
			: base($"{implType.FullName} wrong implemented {wrongImplementedName}") { }
	}
}
