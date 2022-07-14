namespace SecureData.DataBase.Helpers
{
	public static partial class BinaryHelper
	{
		public static unsafe void Write(Span<byte> dest, uint value)
		{
			fixed (byte* ptr = dest.Slice(0, sizeof(uint)))
			{
				Write(ptr, 0, value);
			}
		}

		public static unsafe void Write(Span<byte> dest, long value)
		{
			fixed (byte* ptr = dest.Slice(0, sizeof(long)))
			{
				Write(ptr, 0, value);
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

		public static unsafe void Write(byte* ptr, int offset, uint value)
		{
			*(uint*)(ptr + offset) = value;
		}
		public static unsafe void Write(byte* ptr, int offset, long value)
		{
			*(long*)(ptr + offset) = value;
		}
		public static unsafe void Write(byte* ptr, int offset, bool value)
		{
			*(ptr + offset) = (byte)(value ? 1 : 0);
		}
		public static unsafe void Write(byte* ptr, int offset, string value, int fixedSize)
		{
			Span<byte> s_ptr = new Span<byte>(ptr + offset, fixedSize);
			int bytesWritten = Encoding.GetBytes(value, s_ptr);
			if (bytesWritten < fixedSize)
			{
				s_ptr[bytesWritten] = 0; //null terminate
				MemoryHelper.RNG(s_ptr.Slice(bytesWritten + 1));
			}
		}
	}
}
