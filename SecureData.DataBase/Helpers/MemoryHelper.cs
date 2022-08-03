using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecureData.Storage.Helpers
{
	public static class MemoryHelper
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Span<TTo> As<TTo>(Span<byte> span) where TTo : struct
			=> MemoryMarshal.Cast<byte, TTo>(span);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ReadOnlySpan<TTo> As<TTo>(ReadOnlySpan<byte> span) where TTo : struct
			=> MemoryMarshal.Cast<byte, TTo>(span);

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Span<byte> AsBytes<TFrom>(Span<TFrom> span) where TFrom : struct
			=> MemoryMarshal.AsBytes(span);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ReadOnlySpan<byte> AsBytes<TFrom>(ReadOnlySpan<TFrom> span) where TFrom : struct
			=> MemoryMarshal.AsBytes(span);

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void RNG(Span<byte> data)
		{
			RandomNumberGenerator.Fill(data);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void ZeroOut(Span<byte> data)
		{
			CryptographicOperations.ZeroMemory(data);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Copy(ReadOnlySpan<byte> source, Span<byte> destination)
			=> source.CopyTo(destination);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static bool Compare(ReadOnlySpan<byte> array1, ReadOnlySpan<byte> array2)
			=> array1.SequenceEqual(array2);
	}
}
