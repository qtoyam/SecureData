global using SecureData.DataBase.Helpers;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecureData.DataBase.Helpers
{
	public static class MemoryHelper
	{
		public static void RNG(Span<byte> data)
		{
			System.Security.Cryptography.RandomNumberGenerator.Fill(data);
		}

		public static void ZeroOut(Span<byte> data)
		{
			System.Security.Cryptography.CryptographicOperations.ZeroMemory(data);
		}

		public static void Copy(ReadOnlySpan<byte> source, Span<byte> destination)
			=> source.CopyTo(destination);

		public static bool Compare(ReadOnlySpan<byte> array1, ReadOnlySpan<byte> array2)
			=> array1.SequenceEqual(array2);

		//public unsafe static ReadOnlySpan<byte> StructToReadOnlySpan<T>(in T value) where T : struct
		//	=> MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in value), 1));

		//public unsafe static Span<byte> StructToSpan<T>(in T value) where T : struct
		//	=> MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref Unsafe.AsRef(in value), 1));
	}
}
