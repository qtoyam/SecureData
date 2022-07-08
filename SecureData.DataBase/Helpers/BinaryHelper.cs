namespace SecureData.DataBase.Helpers
{
	internal static class BinaryHelper
	{
		public static unsafe void Write(Span<byte> dest, uint value)
		{
			fixed(byte* ptr = dest)
			{
				*(uint*)ptr = value;
			}
		}

		public static unsafe void Write(Span<byte> dest, long value)
		{
			fixed (byte* ptr = dest)
			{
				*(long*)ptr = value;
			}
		}

		public static unsafe void Write(Span<byte> dest, bool value)
		{
			dest[0] = (byte)(value ? 1 : 0);
		}

		public static void Write(Span<byte> dest, ReadOnlySpan<byte> source)
		{
			source.CopyTo(dest);
		}
	}
}
