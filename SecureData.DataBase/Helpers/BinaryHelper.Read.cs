using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Helpers
{
	//READ
	public static partial class BinaryHelper
	{
		public static unsafe UInt32 ReadUInt32(ReadOnlySpan<byte> bytes)
		{
			fixed(byte* bytes_ptr = bytes.Slice(0, sizeof(UInt32)))
			{
				return ReadUInt32(bytes_ptr, 0);
			}
		}

		public static unsafe UInt32 ReadUInt32(byte* ptr, int byteOffset)
		{
			return *(UInt32*)(ptr + byteOffset);
		}
		public static unsafe DateTime ReadDateTime(byte* ptr, int byteOffset)
		{
			return DateTime.FromBinary(*(long*)(ptr + byteOffset));
		}
		public static unsafe bool ReadBool(byte* ptr, int byteOffset)
		{
			return ptr[byteOffset] != 0;
		}
		public static unsafe string ReadString(byte* ptr, int byteOffset)
		{
			return Encoding.GetString(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(ptr + byteOffset));
		}
	}
}
