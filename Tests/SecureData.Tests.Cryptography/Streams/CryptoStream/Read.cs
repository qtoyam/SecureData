namespace SecureData.Tests.Cryptography.Streams.CryptoStream
{
	public class ReadTests : CryptoStreamTest
	{
		[Fact]
		public void Read()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				bcs.Read(actual, 0, DataSize);
			}

			Assert.Equal(Data, actual);
		}
		[Fact]
		public void ReadBlocks()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				for (int i = 0; i < DataSize; i += Offset)
				{
					bcs.Read(actual, i, Offset);
				}
			}

			Assert.Equal(Data, actual);
		}

		[Fact]
		public void ReadSpan()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				bcs.Read(actual);
			}

			Assert.Equal(Data, actual);
		}
		[Fact]
		public void ReadSpanBlocks()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				for (int i = 0; i < DataSize; i += Offset)
				{
					bcs.Read(actual.AsSpan(i, Offset));
				}
			}

			Assert.Equal(Data, actual);
		}

		[Fact]
		public async Task ReadMemoryAsync()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				await bcs.ReadAsync(actual);
			}

			Assert.Equal(Data, actual);
		}
		[Fact]
		public async Task ReadMemoryBlocksAsync()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(DataEncrypted))
			{
				for (int i = 0; i < DataSize; i+=Offset)
				{
					await bcs.ReadAsync(actual.AsMemory(i, Offset));
				}
			}

			Assert.Equal(Data, actual);
		}
	}
}
