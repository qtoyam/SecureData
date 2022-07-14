global using static SecureData.Tests.Helpers;

namespace SecureData.Tests
{
	internal static class Helpers
	{
		public static readonly int Seed;
		public static Random Random;
		static Helpers()
		{
			Seed = new Random().Next();
			Random = new Random(Seed);
		}

		public static void SetSeed(int seed)
		{
			Random = new Random(seed);
		}
		public static void RNG(Span<byte> arr)
		{
			Random.NextBytes(arr);
		}

		public static void RNG(Span<byte> arr1, Span<byte> arr2)
		{
			RNG(arr1);
			RNG(arr2);
		}

		public static void RNG(Span<byte> arr1, Span<byte> arr2, Span<byte> arr3)
		{
			RNG(arr1, arr2);
			RNG(arr3);
		}
	}
}
