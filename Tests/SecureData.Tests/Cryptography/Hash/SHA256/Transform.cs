using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.Tests.Cryptography.Hash.SHA256
{
	// NOTE:
	// BPB = bytes per block
	// 2 BPB = calls Transform() each 2 bytes
	public class TransformTests : IDisposable
	{
		private readonly System.Security.Cryptography.SHA256 SHA256CS;
		private readonly SecureData.Cryptography.Hash.SHA256 SHA256MY;

		public TransformTests()
		{
			SHA256CS = System.Security.Cryptography.SHA256.Create();
			SHA256MY = new();
		}

		[Fact]
		public void Transform64MB_BPB1()
		{
			Test(1024 * 1024 * 64, 1);
		}

		[Fact]
		public void Transform64MB_BPB2()
		{
			Test(1024 * 1024 * 64, 2);
		}

		[Fact]
		public void Transform64MB_BPB3()
		{
			Test(1024 * 1024 * 64, 3);
		}

		[Fact]
		public void Transform64MB_BPB63()
		{
			Test(1024 * 1024 * 64, 63);
		}

		[Fact]
		public void Transform64MB_BPB64()
		{
			Test(1024 * 1024 * 64, 64);
		}

		public void Dispose()
		{
			SHA256CS.Dispose();
			SHA256MY.Dispose();
		}

		private void Test(int size, int bpb)
		{
			byte[] input = new byte[size];
			new Random(42).NextBytes(input);
			byte[] expected, actual;
			expected = SHA256CS.ComputeHash(input);

			SHA256MY.Initialize();
			ReadOnlySpan<byte> working;
			int blocks = size / bpb;
			int block_i;
			for (block_i = 0; block_i < blocks; block_i++)
			{
				working = input.AsSpan(block_i * bpb, bpb);
				SHA256MY.Transform(working);
			}
			int remainingBytes = size % bpb;
			working = input.AsSpan(block_i * bpb, remainingBytes);
			SHA256MY.Transform(working);
			actual = SHA256MY.Finalize();

			Assert.Equal(expected, actual);
		}
	}
}
