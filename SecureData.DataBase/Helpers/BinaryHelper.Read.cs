using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Helpers
{
	//READ
	public static partial class BinaryHelper
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Int64 ReadInt64(ReadOnlySpan<byte> source) => MemoryMarshal.Read<long>(source);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static UInt32 ReadUInt32(ReadOnlySpan<byte> source) => MemoryMarshal.Read<uint>(source);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static DateTime ReadDateTime(ReadOnlySpan<byte> source) => MemoryMarshal.Read<DateTime>(source).ToLocalTime();
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool ReadBool(ReadOnlySpan<byte> source) => source[0] != 0;
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static string ReadString(ReadOnlySpan<byte> source)
		{
			int l = source.IndexOf((byte)0);
			if (l == -1)
			{
				l = source.Length;
			}
			return Encoding.GetString(source.Slice(0, l));
		}
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ReadBytes(ReadOnlySpan<byte> source, Span<byte> destination) => source.CopyTo(destination);
	}
}
