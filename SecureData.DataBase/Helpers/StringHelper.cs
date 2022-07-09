using System.Runtime.InteropServices;
using System.Text;

namespace SecureData.DataBase.Helpers
{
	internal static class StringHelper
	{
		private static readonly Encoding _enc = Encoding.UTF8;
		public static unsafe string GetStringFromNullTerminatedBytes(byte* pointer)
		{
			ReadOnlySpan<byte> res = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(pointer);
			return _enc.GetString(res);
		}


		//public static int Write(Span<byte> s_buffer, string str, int fixedSize)
		//{
		//	int encodedBytes = _enc.GetBytes(str, s_buffer.Slice(0, fixedSize));
		//	s_buffer[encodedBytes] = 0; //null terminate
		//	return encodedBytes + 1;
		//}

		/// <summary>
		/// Copy <paramref name="str"/> to <paramref name="s_buffer"/> as UTF8 string and fills extra space with RNG bytes.
		/// </summary>
		/// <param name="s_buffer"></param>
		/// <param name="str"></param>
		public static void WriteWithRNG(Span<byte> s_buffer, string str)
		{
			int bytesEnc = _enc.GetBytes(str, s_buffer);
			if (bytesEnc != s_buffer.Length)
			{
				s_buffer[bytesEnc] = 0; //null terminate
				MemoryHelper.RNG(s_buffer.Slice(bytesEnc + 1));
			}
		}
	}
}
