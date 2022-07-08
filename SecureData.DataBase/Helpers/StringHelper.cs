using System.Runtime.InteropServices;
using System.Text;

namespace SecureData.DataBase.Helpers
{
	internal static class StringHelper
	{
		private static readonly Encoding _enc = Encoding.UTF8;
		public static string GetStringFromNullTerminatedBytes(ReadOnlySpan<byte> bytes)
		{
			ReadOnlySpan<byte> res;
			unsafe
			{
				fixed (byte* ptr = bytes)
				{
					res = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(ptr);
				}
			}
			return _enc.GetString(res);
		}

		/// <summary>
		/// Writes <paramref name="str"/> to <paramref name="s_buffer"/> with <paramref name="fixedSize"/> in bytes.
		/// </summary>
		/// <param name="s_buffer"></param>
		/// <param name="str">size should NOT be greater than <paramref name="fixedSize"/>.</param>
		/// <param name="fixedSize"></param>
		/// <returns>Written bytes.</returns>
		//public static int Write(Span<byte> s_buffer, string str, int fixedSize)
		//{
		//	int encodedBytes = _enc.GetBytes(str, s_buffer.Slice(0, fixedSize));
		//	s_buffer[encodedBytes] = 0; //null terminate
		//	return encodedBytes + 1;
		//}

		//TODO: test
		public static void WriteWithRNG(Span<byte> s_buffer, string str)
		{
			int encodedBytes = _enc.GetBytes(str, s_buffer);
			s_buffer[encodedBytes] = 0; //null terminate
			Utils.RNG(s_buffer.Slice(encodedBytes + 1));
		}
	}
}
