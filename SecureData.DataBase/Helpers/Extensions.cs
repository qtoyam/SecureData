using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.DataBase.Helpers
{
	internal static class Extensions
	{
		public static bool EOF(this Stream stream) => stream.Position == stream.Length;
	}
}
