using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.DataBase.Helpers
{
	internal static class BinaryHelper
	{
		public static unsafe void WriteUInt32(Span<byte> dest, uint value)
		{
			fixed(byte* ptr = dest)
			{
				*(uint*)ptr = value;
			}
		}

		public static void Write(Span<byte> dest, ReadOnlySpan<byte> source)
		{
			source.CopyTo(dest);
		}
	}
}
