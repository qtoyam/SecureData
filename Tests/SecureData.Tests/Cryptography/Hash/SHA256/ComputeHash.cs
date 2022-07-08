using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.Tests.Cryptography.Hash.SHA256
{
	public class ComputeHashTest
	{
		[Fact]
		public void ComputeHash256MB()
		{
			Test(1024 * 1024 * 256);
		}

		[Fact]
		public void ComputeHash256MB_63ExtraBytes()
		{
			Test(1024 * 1024 * 256 + 63);
		}

		private static void Test(int size)
		{
			byte[] input = new byte[size];
			new Random(42).NextBytes(input);
			using var sha256CS = System.Security.Cryptography.SHA256.Create();
			byte[] expected, actual;
			expected = sha256CS.ComputeHash(input);

			actual = SecureData.Cryptography.Hash.SHA256.ComputeHash(input);

			Assert.Equal(expected, actual);
		}
	}
}
