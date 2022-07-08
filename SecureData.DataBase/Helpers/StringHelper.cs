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

		//str's size should NOT be greater than fixedSize
		public static void Write(Span<byte> bytes, string str, int fixedSize)
		{
			_enc.GetBytes(str, bytes.Slice(0, fixedSize));
		}
	}
}
