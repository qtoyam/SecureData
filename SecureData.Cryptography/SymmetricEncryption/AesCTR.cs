
using System.Runtime.InteropServices;

namespace SecureData.Cryptography.SymmetricEncryption
{
	public class Aes : IDisposable
	{
		#region Consts
		public const int BlockSize = 16;
		public const int IVSize = BlockSize;
		public const int KeySize = 32;
		public const int BlockSizeShift = 4;
		#endregion

		private readonly AesSafeHandle _handle;

		public uint Counter { get; set; }

		public Aes()
		{
			Native.AES_CreateHandle(out _handle);
			Counter = 0;
		}
		public Aes(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : this()
		{
			SetKeyIV(key, iv);
		}

		public void SetIV(ReadOnlySpan<byte> iv)
		{
			if (iv.Length != IVSize)
			{
				throw new ArgumentException($"Required IV size: {IVSize}", nameof(iv));
			}
			unsafe
			{
				fixed (byte* iv_ptr = iv)
				{
					Native.AES_SetIV(_handle, iv_ptr);
				}
			}
		}
		public void SetKey(ReadOnlySpan<byte> key)
		{
			if (key.Length != KeySize)
			{
				throw new ArgumentException($"Required key size: {KeySize}", nameof(key));
			}
			unsafe
			{
				fixed (byte* key_ptr = key)
				{
					Native.AES_SetKey(_handle, key_ptr);
				}
			}
		}
		public void SetKeyIV(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
		{
			SetIV(iv);
			SetKey(key);
		}

		public void Transform(ReadOnlySpan<byte> input, Span<byte> output, uint initialCounter)
		{
			if (input.Length != output.Length)
			{
				throw new ArgumentException($"{nameof(input)} length must be equal to {nameof(output)} length");
			}
			else if (!IsValidSize(input.Length))
			{
				throw new ArgumentException($"Buffers length must divide by block size: {BlockSize}");
			}
			unsafe
			{
				fixed (byte* input_ptr = input, output_ptr = output)
				{
					Native.AES_Encrypt(_handle, input_ptr, output_ptr, initialCounter, (ulong)input.Length);
				}
			}
		}
		public void Transform(Span<byte> input, uint initialCounter)
		{
			Transform(input, input, initialCounter);
		}
		public void TransformBlock(ReadOnlySpan<byte> input, Span<byte> output, uint initialCounter)
		{
			if (input.Length != output.Length)
			{
				throw new ArgumentException($"{nameof(input)} length must be equal to {nameof(output)} length");
			}
			else if (input.Length != BlockSize)
			{
				throw new ArgumentException($"Buffers length must be equal to block size: {BlockSize}");
			}
			unsafe
			{
				fixed (byte* input_ptr = input, output_ptr = output)
				{
					Native.AES_EncryptBlock(_handle, input_ptr, output_ptr, initialCounter);
				}
			}
		}
		public void TransformBlock(Span<byte> input, uint initialCounter)
		{
			TransformBlock(input, input, initialCounter);
		}

		public void Transform(ReadOnlySpan<byte> input, Span<byte> output)
		{
			Transform(input, output, Counter);
			Counter += ((uint)input.Length) >> BlockSizeShift;
		}
		public void Transform(Span<byte> input)
		{
			Transform(input, input);
		}
		public void TransformBlock(ReadOnlySpan<byte> input, Span<byte> output)
		{
			TransformBlock(input, output, Counter);
			++Counter;
		}
		public void TransformBlock(Span<byte> input)
		{
			TransformBlock(input, input);
		}

		public void Dispose()
		{
			_handle.Dispose();
			GC.SuppressFinalize(this);
		}

		#region Helpers
		public static bool IsValidSize(int size)
		{
			return (size & (BlockSize - 1)) == 0;
		}
		public static bool IsValidSize(long size)
		{
			return (size & (BlockSize - 1)) == 0;
		}
		#endregion
		private sealed class AesSafeHandle : SafeHandle
		{
			public AesSafeHandle() : base(IntPtr.Zero, true) { }
			public override bool IsInvalid => handle == IntPtr.Zero;
			protected override bool ReleaseHandle()
			{
				Native.AES_DestroyHandle(handle);
				return true;
			}
		}
		private static class Native
		{
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void AES_CreateHandle(out AesSafeHandle handle);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void AES_SetIV(AesSafeHandle handle, void* iv);
			[DllImport(DllImportManager.DllName)]
			public static extern unsafe void AES_DestroyHandle(IntPtr handle);

			#region Default
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESDF_SetKey(AesSafeHandle handle, void* key);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESDF_Encrypt(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter, UInt64 size);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESDF_EncryptBlock(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter);
			#endregion
			#region TTables
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESTT_SetKey(AesSafeHandle handle, void* key);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESTT_Encrypt(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter, UInt64 size);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESTT_EncryptBlock(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter);
			#endregion
			#region NI
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESNI_SetKey(AesSafeHandle handle, void* key);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESNI_Encrypt(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter, UInt64 size);
			[DllImport(DllImportManager.DllName)]
			private static extern unsafe void AESNI_EncryptBlock(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter);
			#endregion

			public static unsafe void AES_SetKey(AesSafeHandle handle, void* key)
			{
				if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
				{
					AESNI_SetKey(handle, key);
				}
				else
				{
					AESTT_SetKey(handle, key);
				}
			}
			public static unsafe void AES_Encrypt(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter, UInt64 size)
			{
				if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
				{
					AESNI_Encrypt(handle, input, output, initialCounter, size);
				}
				else
				{
					AESTT_Encrypt(handle, input, output, initialCounter, size);
				}
			}
			public static unsafe void AES_EncryptBlock(AesSafeHandle handle, void* input, void* output, UInt32 initialCounter)
			{
				if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
				{
					AESNI_EncryptBlock(handle, input, output, initialCounter);
				}
				else
				{
					AESNI_EncryptBlock(handle, input, output, initialCounter);
				}
			}
		}
	}
}
