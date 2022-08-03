using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SecureData.Cryptography.Hash
{
	public class Argon2dOptions
	{
		public uint TimeCost { get; set; } = 5;
		public uint MemoryCost { get; set; } = 64 * 1024;
		public uint Parallelism { get; set; } = 1;

		public Argon2dOptions(uint timeCost, uint memoryCost, uint parallelism)
		{
			TimeCost = timeCost;
			MemoryCost = memoryCost;
			Parallelism = parallelism;
		}
		public Argon2dOptions(ReadOnlySpan<byte> rawOptions)
		{
			TimeCost = BinaryPrimitives.ReadUInt32LittleEndian(rawOptions.Slice(0 * sizeof(uint), sizeof(uint)));
			MemoryCost = BinaryPrimitives.ReadUInt32LittleEndian(rawOptions.Slice(1 * sizeof(uint), sizeof(uint)));
			Parallelism = BinaryPrimitives.ReadUInt32LittleEndian(rawOptions.Slice(2 * sizeof(uint), sizeof(uint)));
		}

		public void Serialize(Span<byte> buffer)
		{
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0 * sizeof(uint), sizeof(uint)), TimeCost);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(1 * sizeof(uint), sizeof(uint)), MemoryCost);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(2 * sizeof(uint), sizeof(uint)), Parallelism);
		}
	}

	public class Argon2d
	{
		public static unsafe void ComputeHash(Argon2dOptions options,
			ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> hash)
		{
			fixed (byte* password_ptr = password, salt_ptr = salt, hash_ptr = hash)
			{
				int res = Native.argon2d_hash_raw(options.TimeCost, options.MemoryCost, options.Parallelism,
					password_ptr, (ulong)password.Length,
					   salt_ptr, (ulong)salt.Length,
						 hash_ptr, (ulong)hash.Length);
				if (res != 0)
				{
					throw new InvalidOperationException($"Argon2d error code: {res}");
				}
			}
		}

		private static class Native
		{
			[DllImport(Library.Argon2)]
			public static extern unsafe int argon2d_hash_raw(
				UInt32 t_cost, UInt32 m_cost,
				UInt32 parallelism, void* pwd,
				ulong pwdlen, void* salt,
				ulong saltlen, void* hash,
				ulong hashlen);
		}
	}
}
