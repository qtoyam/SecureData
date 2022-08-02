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

		private SHA256(SHA256SafeHandle handle, bool isFinal)
		{
			_handle = handle;
			_isFinal = isFinal;
		}

		public SHA256() : this(Native.SHA256_CreateHandle(), false)
		{
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

		public SHA256 Clone()
		{
			SHA256SafeHandle newHandle = Native.SHA256_CreateHandle();
			Native.SHA256_Clone(_handle, newHandle);
			return new SHA256(newHandle, _isFinal);
		}

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
			public static SHA256SafeHandle SHA256_CreateHandle()
			{
				SHA256_CreateHandle(out SHA256SafeHandle handle);
				return handle;
			}

			[DllImport(Library.Crypto)]
			private static extern void SHA256_CreateHandle(out SHA256SafeHandle handle);
			[DllImport(Library.Crypto)]
			public static extern void SHA256_DestroyHandle(IntPtr handle);
			[DllImport(Library.Crypto)]
			public static extern void SHA256_Initialize(SHA256SafeHandle handle);
			[DllImport(Library.Crypto)]
			public static extern unsafe void SHA256_Transform(SHA256SafeHandle handle, void* input, UInt64 size);
			[DllImport(Library.Crypto)]
			public static extern unsafe void SHA256_Finalize(SHA256SafeHandle handle, void* output);
			[DllImport(Library.Crypto)]
			public static extern void SHA256_Clone(SHA256SafeHandle source, SHA256SafeHandle destination);
			[DllImport(Library.Crypto)]
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
