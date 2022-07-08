using System.Runtime.InteropServices;

namespace SecureData.Cryptography.Hash
{
	public sealed class SHA256 : IDisposable
	{
		#region Consts
		public const int HashSize = 32;
		#endregion

		private readonly SHA256SafeHandle _handle;
		private bool _isFinal;

		public SHA256()
		{
			Native.SHA256_CreateHandle(out _handle);
			Initialize();
		}

		/// <summary>
		/// Resets current state.
		/// </summary>
		public void Initialize()
		{
			Native.SHA256_Initialize(_handle);
			_isFinal = false;
		}

		/// <summary>
		/// Updates current hash value.
		/// </summary>
		/// <param name="input"></param>
		public void Transform(ReadOnlySpan<byte> input)
		{
			ThrowIfFinal();
			unsafe
			{
				fixed (byte* input_ptr = input)
				{
					Native.SHA256_Transform(_handle, input_ptr, (ulong)input.Length);
				}
			}
		}

		/// <summary>
		/// Compute final hash and store it in <paramref name="hash"/>.
		/// </summary>
		/// <param name="hash"></param>
		public void Finalize(Span<byte> hash)
		{
			ThrowIfFinal();
			EnsureHashBuffer(hash);
			unsafe
			{
				fixed (byte* hash_ptr = hash)
				{
					Native.SHA256_Finalize(_handle, hash_ptr);
				}
			}
			_isFinal = true;
		}

		/// <summary>
		/// Compute final hash.
		/// </summary>
		/// <returns>Actual hash</returns>
		public byte[] Finalize()
		{
			byte[] hash = new byte[HashSize];
			Finalize(hash);
			return hash;
		}

		public static void ComputeHash(ReadOnlySpan<byte> input, Span<byte> hash)
		{
			EnsureHashBuffer(hash);
			unsafe
			{
				fixed(byte* input_ptr = input, hash_ptr = hash)
				{
					Native.SHA256_GenerateHash(input_ptr, hash_ptr, (ulong)input.Length);
				}
			}
		}
		public static byte[] ComputeHash(ReadOnlySpan<byte> input)
		{
			byte[] hash = new byte[HashSize];
			ComputeHash(input, hash);
			return hash;
		}

		public void Dispose() => _handle.Dispose();

		private sealed class SHA256SafeHandle : SafeHandle
		{
			public SHA256SafeHandle() : base(IntPtr.Zero, true) { }

			public override bool IsInvalid => handle == IntPtr.Zero;

			protected override bool ReleaseHandle()
			{
				Native.SHA256_DestroyHandle(handle);
				return true;
			}
		}
		private static class Native
		{
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_CreateHandle(out SHA256SafeHandle handle);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_DestroyHandle(IntPtr handle);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_Initialize(SHA256SafeHandle handle);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_Transform(SHA256SafeHandle handle, void* input, UInt64 size);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_Finalize(SHA256SafeHandle handle, void* output);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void SHA256_GenerateHash(void* input, void* output, UInt64 size);
		}

		#region Helpers
		private void ThrowIfFinal()
		{
			if (_isFinal)
			{
				throw new InvalidOperationException("Current state is unmodifiable.");
			}
		}
		private static void EnsureHashBuffer(ReadOnlySpan<byte> hashBuffer)
		{
			if (hashBuffer.Length < HashSize)
			{
				throw new ArgumentException("Small hash buffer size.");
			}
		}
		#endregion
	}
}
