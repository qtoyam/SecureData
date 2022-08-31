using System;
using System.IO;

namespace SecureData.Manager
{
	internal static class Paths
	{
		public readonly static string CurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
		//public readonly static string Databases = Path.Combine(CurrentDirectory, "Data");

		public readonly static string Database = Path.Combine(CurrentDirectory, "data");
	}
}
