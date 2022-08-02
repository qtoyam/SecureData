using System.Reflection;
using System.Runtime.InteropServices;

namespace SecureData.Tests.Cryptography.Aes
{
	public class MiscTests
	{
		[Fact]
		public void Clone()
		{
			Span<byte> data_tmp = new byte[256];

			Span<byte> key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			Span<byte> iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];

			uint counter_1, counter_2;
			Span<byte> data_1 = new byte[1024 * 64];
			Span<byte> data_2 = new byte[data_1.Length];
			RNG(data_1, key, iv, data_tmp);
			data_1.CopyTo(data_2);

			using (SecureData.Cryptography.SymmetricEncryption.AesCtr aes_1 = new(key, iv))
			{
				aes_1.Counter = 42U;
				aes_1.Transform(data_tmp);

				using (var aes_2 = aes_1.Clone())
				{
					aes_2.Transform(data_2);
					counter_2 = aes_2.Counter;
				}
				aes_1.Transform(data_1);
				counter_1 = aes_1.Counter;
			}

			Assert.Equal(counter_1, counter_2);
			AssertExt.Equal(data_1, data_2);
		}

		[Fact]
		public void MoveNextIV()
		{
			const ulong moveBy = ulong.MaxValue / 2;
			Span<byte> exp_data = new byte[1024*64];
			Span<byte> act_data = new byte[exp_data.Length];
			Span<byte> key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			Span<byte> iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			RNG(key, iv, exp_data);
			exp_data.CopyTo(act_data);
			Span<byte> exp_iv = new byte[iv.Length];
			iv.CopyTo(exp_iv);
			{
				Span<ulong> exp_iv64 = MemoryMarshal.Cast<byte, ulong>(exp_iv);
				exp_iv64[0] += moveBy;
			}
			using(SecureData.Cryptography.SymmetricEncryption.AesCtr exp_aes = new(key, exp_iv))
			{
				exp_aes.Transform(exp_data);
			}

			using (SecureData.Cryptography.SymmetricEncryption.AesCtr act_aes = new(key, iv))
			{
				act_aes.MoveNextIV(moveBy);
				act_aes.Transform(act_data);
			}

			AssertExt.Equal(exp_data, act_data);
		}

		[Fact]
		public void MovePrevIV()
		{
			const ulong moveBy = ulong.MaxValue / 2 + 204;
			Span<byte> exp_data = new byte[1024 * 64];
			Span<byte> act_data = new byte[exp_data.Length];
			Span<byte> key = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.KeySize];
			Span<byte> iv = new byte[SecureData.Cryptography.SymmetricEncryption.AesCtr.IVSize];
			RNG(key, iv, exp_data);
			exp_data.CopyTo(act_data);
			Span<byte> exp_iv = new byte[iv.Length];
			iv.CopyTo(exp_iv);
			{
				Span<ulong> exp_iv64 = MemoryMarshal.Cast<byte, ulong>(exp_iv);
				exp_iv64[0] -= moveBy;
			}
			using (SecureData.Cryptography.SymmetricEncryption.AesCtr exp_aes = new(key, exp_iv))
			{
				exp_aes.Transform(exp_data);
			}

			using (SecureData.Cryptography.SymmetricEncryption.AesCtr act_aes = new(key, iv))
			{
				act_aes.MovePrevIV(moveBy);
				act_aes.Transform(act_data);
			}

			AssertExt.Equal(exp_data, act_data);
		}

		[Fact]
		public void Clear()
		{
			using(SecureData.Cryptography.SymmetricEncryption.AesCtr aes = new SecureData.Cryptography.SymmetricEncryption.AesCtr())
			{
				aes.Clear();
				var handle = (SafeHandle)
					aes.GetType()
					.GetField("_handle", BindingFlags.Instance | BindingFlags.NonPublic)!
					.GetValue(aes)!;
				var ptr = handle.DangerousGetHandle();
				for (int i = 0; i < 256; i++)
				{
					Assert.Equal(0, Marshal.ReadByte(ptr, i));
				}
			}
		}
	}
}
