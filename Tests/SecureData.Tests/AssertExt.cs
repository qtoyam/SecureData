using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.Tests
{
	internal static class AssertExt
	{
		public static void Equal(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
		{
			Assert.True(expected.SequenceEqual(actual));
		}

		public static void Equal(ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> actual)
		{
			Equal(expected.Span, actual.Span);
		}
	}
}
