using System.Runtime.CompilerServices;

namespace SecureData.Tests;

internal static class RandomHelper
{
	public static readonly int Seed;
	public static Random Rand;
	static RandomHelper()
	{
		Seed = new Random().Next();
		Rand = new Random(Seed);
	}

	public static void SetSeed(int seed)
	{
		Rand = new Random(seed);
	}
	public static void RNG(Span<byte> arr)
	{
		Rand.NextBytes(arr);
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

	public static bool TryDeleteFile(string path)
	{
		if(!File.Exists(path))
		{
			return false;
		}
		File.Delete(path);
		return true;
	}
}

public class FileHandler : IDisposable
{
	private readonly LinkedList<string> _files = new();

	public string GetPath([CallerMemberName] string caller = "")
	{
		string path = caller + ".tmp"; //test temporary
		while(_files.Contains(path))
		{
			path += "_t";
		}
		if(File.Exists(path))
		{
			File.Delete(path);
		}
		_files.AddLast(path);
		return path;
	}

	void IDisposable.Dispose()
	{
		foreach(var file in _files)
		{
			if(File.Exists(file))
			{
				File.Delete(file);
			}
		}
		GC.SuppressFinalize(this);
	}
}
