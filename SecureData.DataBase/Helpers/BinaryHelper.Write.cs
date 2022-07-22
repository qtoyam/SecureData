using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Helpers
{
	public static partial class BinaryHelper
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Write(Span<byte> destination, bool value) => destination[0] = (byte)(value ? 1 : 0);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Write(Span<byte> destination, uint value) => MemoryMarshal.Write(destination, ref value);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Write(Span<byte> destination, DateTime value)
		{
			DateTime utc = value.ToUniversalTime();
			MemoryMarshal.Write(destination, ref utc);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void WriteWRNG(Span<byte> destination, ReadOnlySpan<char> value)
		{
			int bytesWritten = Encoding.GetBytes(value, destination);
			if(bytesWritten < destination.Length)
			{
				destination[bytesWritten] = 0; //null terminate
				MemoryHelper.RNG(destination.Slice(bytesWritten + 1)); //fill extra with RNG
			}
		}
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Write(Span<byte> dest, ReadOnlySpan<byte> source) => source.CopyTo(dest);
	}
}
