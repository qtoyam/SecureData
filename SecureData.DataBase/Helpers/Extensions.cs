namespace SecureData.DataBase.Helpers
{
	public static class Extensions
	{
		public static bool EOF(this Stream stream) => stream.Position == stream.Length;
	}
}
