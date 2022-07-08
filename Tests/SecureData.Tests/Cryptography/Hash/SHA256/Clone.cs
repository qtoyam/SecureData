using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.Tests.Cryptography.Hash.SHA256
{
	public class CloneTests
	{
		[Fact]
		public void Clone()
		{
			SecureData.Cryptography.Hash.SHA256 source = new();
			byte[] someData = new byte[256 + 5];
			new Random(42).NextBytes(someData);
			source.Transform(someData);
			byte[] expected, actual;

			var newSha = source.Clone();

			expected = source.Finalize();
			actual = newSha.Finalize();

			Assert.Equal(expected, actual);
		}
	}
}
