namespace SecureData.Tests.Cryptography.Streams.CryptoStream
{
	public class WriteTests : CryptoStreamTest
	{
		[Fact]
		public void Write()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				bcs.Write(Data, 0, DataSize);
			}

			Assert.Equal(DataEncrypted, actual);
		}
		[Fact]
		public void WriteBlocks()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				for (int i = 0; i < DataSize; i += Offset)
				{
					bcs.Write(Data, i, Offset);
				}
			}

			Assert.Equal(DataEncrypted, actual);
		}

		[Fact]
		public void WriteSpan()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				bcs.Write(Data);
			}

			Assert.Equal(DataEncrypted, actual);
		}
		[Fact]
		public void WriteSpanBlocks()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				for (int i = 0; i < DataSize; i += Offset)
				{
					bcs.Write(Data.AsSpan(i, Offset));
				}
			}

			Assert.Equal(DataEncrypted, actual);
		}

		[Fact]
		public async Task WriteMemoryAsync()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				await bcs.WriteAsync(Data);
			}

			Assert.Equal(DataEncrypted, actual);
		}
		[Fact]
		public async Task WriteMemoryAsyncBlocks()
		{
			byte[] actual = CreateActualBuffer();
			using (var bcs = BCSOverArray(actual))
			{
				for (int i = 0; i < DataSize; i += Offset)
				{
					await bcs.WriteAsync(Data.AsMemory(i, Offset));
				}
			}

			Assert.Equal(DataEncrypted, actual);
		}

		[Fact]
		public void WriteFast()
		{
			var d = CreateDataCopy();
			var actual = CreateActualBuffer();

			using(var bcs = BCSOverArray(actual))
			{
				bcs.WriteFast(d);
			}

			Assert.Equal(DataEncrypted, d);
		}
		[Fact]
		public async Task WriteFastAsync()
		{
			var d = CreateDataCopy();
			var actual = CreateActualBuffer();

			using (var bcs = BCSOverArray(actual))
			{
				await bcs.WriteFastAsync(d);
			}

			Assert.Equal(DataEncrypted, d);
		}
	}

}
