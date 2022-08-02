using System.Runtime.InteropServices;

namespace SecureData.Cryptography.Hash
{
	public class Argon2d
	{
		public static unsafe void ComputeHash(uint time_cost, uint memory_cost, uint parallelism,
			ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> hash)
		{
			fixed (byte* password_ptr = password, salt_ptr = salt, hash_ptr = hash)
			{
				int res = Native.argon2d_hash_raw(time_cost, memory_cost, parallelism,
					password_ptr, (ulong)password.Length, 
					   salt_ptr, (ulong)salt.Length, 
						 hash_ptr, (ulong)hash.Length);
				if(res != 0)
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
