namespace SecureData.Tests
{
	internal static class RandomHelper
	{
		public static readonly int Seed;
		public static Random Random;
		static RandomHelper()
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

		public static void RNG(Span<byte> arr1, Span<byte> arr2, Span<byte> arr3, Span<byte> arr4)
		{
			RNG(arr1, arr2, arr3);
			RNG(arr4);
		}
	}
}
