using System.Buffers;
using System.Security.Cryptography;

using SecureData.Cryptography.SymmetricEncryption;

namespace SecureData.Cryptography.Streams
{
	public sealed class BlockCryptoStream : Stream
	{
		private static class Consts
		{
			public const int RentedHashBufferSize = 64 * 1024;
		}

		private readonly Stream _baseStream;
		private readonly bool _closeOnDispose;
		private readonly bool _autoDisposeAes;
		private readonly Aes256Ctr _aes;

		private uint CTR { get; set; }
		private void UpdateCTR() => CTR = (uint)(Position >> Aes256Ctr.BlockSizeShift);

		public BlockCryptoStream(Stream baseStream, Aes256Ctr aes, bool autoDisposeAes, bool closeOnDispose = false)
		{
			if (!Aes256Ctr.IsValidSize(baseStream.Length))
			{
				throw new ArgumentException($"FileStream length is not dividable by block size: {Aes256Ctr.BlockSize}");
			}
			_baseStream = baseStream;
			_closeOnDispose = closeOnDispose;
			_autoDisposeAes = autoDisposeAes;
			_aes = aes;
			UpdateCTR(); //if baseStream position != 0
		}
		public BlockCryptoStream(Stream baseStream, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool closeOnDispose = false)
			: this(baseStream, new Aes256Ctr(key, iv), true, closeOnDispose: closeOnDispose)
		{ }
		public BlockCryptoStream(string path, FileStreamOptions options, Aes256Ctr aes, bool autoDisposeAes)
			: this(new FileStream(path, options), aes, autoDisposeAes, closeOnDispose: true)
		{ }
		public BlockCryptoStream(string path, FileStreamOptions options, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
			: this(path, options, new Aes256Ctr(key, iv), true)
		{ }

		public override bool CanRead => _baseStream.CanRead;
		public override bool CanSeek => _baseStream.CanSeek;
		public override bool CanWrite => _baseStream.CanWrite;
		public override long Length => _baseStream.Length;
		public override long Position
		{
			get => _baseStream.Position;
			set
			{
				ThrowIfWrongPosition(value);
				_baseStream.Position = value;
				UpdateCTR();
			}
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			var pos = _baseStream.Seek(offset, origin);
			ThrowIfWrongPosition(pos);
			UpdateCTR();
			return pos;
		}
		public override void SetLength(long value)
		{
			if (!Aes256Ctr.IsValidSize(value))
			{
				throw new ArgumentException($"Value is not dividable by block size: {Aes256Ctr.BlockSize}", nameof(value));
			}
			if (value > Length)
			{
				throw new InvalidOperationException("Growing file without filling it is dangerous!");
			}
			_baseStream.SetLength(value);
			UpdateCTR();
		}

		public override void Flush() => _baseStream.Flush();
		public override Task FlushAsync(CancellationToken cancellationToken) => _baseStream.FlushAsync(cancellationToken);

		public override int Read(Span<byte> buffer)
		{
			ThrowIfWrongCount(buffer.Length);
			var res = _baseStream.Read(buffer);
			_aes.Transform(buffer, CTR);
			UpdateCTR();
			return res;
		}
		public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
		public override int ReadByte() => throw new NotSupportedException();
		public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			ThrowIfWrongCount(buffer.Length);
			var res = await _baseStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
			_aes.Transform(buffer.Span, CTR);
			UpdateCTR();
			return res;
		}
		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
			ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

		public override void Write(ReadOnlySpan<byte> buffer)
		{
			ThrowIfWrongCount(buffer.Length);
			var sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
			Span<byte> s_encryptedBuffer = sharedBuffer.AsSpan(0, buffer.Length);
			_aes.Transform(buffer, s_encryptedBuffer, CTR);
			_baseStream.Write(s_encryptedBuffer);
			UpdateCTR();
			ArrayPool<byte>.Shared.Return(sharedBuffer);
		}
		public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
		public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
		{
			ThrowIfWrongCount(buffer.Length);
			var sharedBuffer = MemoryPool<byte>.Shared.Rent(buffer.Length);
			Memory<byte> m_sharedBuffer = sharedBuffer.Memory.Slice(0, buffer.Length);
			try
			{
				_aes.Transform(buffer.Span, m_sharedBuffer.Span, CTR);
				await _baseStream.WriteAsync(m_sharedBuffer, cancellationToken).ConfigureAwait(false);
				UpdateCTR();
			}
			finally
			{
				sharedBuffer.Dispose();
			}
		}

		/// <summary>
		/// Encrypt <paramref name="buffer"/> in-place and write it to stream.
		/// </summary>
		/// <param name="buffer"></param>
		public void WriteFast(Span<byte> buffer)
		{
			ThrowIfWrongCount(buffer.Length);
			_aes.Transform(buffer, CTR);
			_baseStream.Write(buffer);
			UpdateCTR();
		}
		/// <summary>
		/// Encrypt <paramref name="buffer"/> in-place and write it to stream asynchronously.
		/// </summary>
		/// <param name="buffer"></param>
		public async ValueTask WriteFastAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			ThrowIfWrongCount(buffer.Length);
			_aes.Transform(buffer.Span, CTR);
			await _baseStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
			UpdateCTR();
		}

		/// <summary>
		/// Read <paramref name="buffer"/> WITHOUT encryption.
		/// </summary>
		/// <param name="buffer"></param>
		public void ReadThroughEncryption(Span<byte> buffer)
		{
			ThrowIfWrongCount(buffer.Length);
			_baseStream.Read(buffer);
			UpdateCTR();
		}
		/// <summary>
		/// Write <paramref name="buffer"/> WITHOUT encryption.
		/// </summary>
		/// <param name="buffer"></param>
		public void WriteThroughEncryption(ReadOnlySpan<byte> buffer)
		{
			ThrowIfWrongCount(buffer.Length);
			_baseStream.Write(buffer);
			UpdateCTR();
		}

		private static void ThrowIfWrongPosition(long pos)
		{
			if (!Aes256Ctr.IsValidSize(pos))
			{
				throw new InvalidOperationException($"Position is not dividable by block size: {Aes256Ctr.BlockSize}");
			}
		}
		private static void ThrowIfWrongCount(int count)
		{
			if (!Aes256Ctr.IsValidSize(count))
			{
				throw new InvalidOperationException($"Count is not dividable by block size: {Aes256Ctr.BlockSize}");
			}
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (_autoDisposeAes)
				{
					_aes.Dispose();
				}
				if (_closeOnDispose)
				{
					_baseStream.Dispose();
				}
			}
			base.Dispose(disposing);
		}
		public override async ValueTask DisposeAsync()
		{
			if (_autoDisposeAes)
			{
				_aes.Dispose();
			}
			if (_closeOnDispose)
			{
				await _baseStream.DisposeAsync().ConfigureAwait(false);
			}
			await base.DisposeAsync().ConfigureAwait(false);
			GC.SuppressFinalize(this);
		}
	}
}
