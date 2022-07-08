global using SecureData.DataBase.Helpers;


namespace SecureData.DataBase.Helpers
{
	internal static class Utils
	{
		public static void RNG(Span<byte> data)
		{
			System.Security.Cryptography.RandomNumberGenerator.Fill(data);
		}
	}
}
