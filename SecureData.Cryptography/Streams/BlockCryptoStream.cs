using System;
using System.Buffers;
using System.Runtime.CompilerServices;

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
		private readonly Aes _aes;

		//TODO: remove this, cauze AesCTR have its own
		//private uint CTR { get; set; }
		//private void UpdateCTR() => CTR = (uint)(Position >> Aes.BlockSizeShift);

		private void UpdCTR() => _aes.Counter = (uint)(Position >> Aes.BlockSizeShift);

		public BlockCryptoStream(Stream baseStream, Aes aes, bool autoDisposeAes, bool closeOnDispose = false)
		{
			if (!Aes.IsValidSize(baseStream.Length))
			{
				throw new ArgumentException($"FileStream length is not dividable by block size: {Aes.BlockSize}");
			}
			_baseStream = baseStream;
			_closeOnDispose = closeOnDispose;
			_autoDisposeAes = autoDisposeAes;
			_aes = aes;
			UpdCTR(); //if baseStream position != 0
		}
		public BlockCryptoStream(Stream baseStream, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool closeOnDispose = false)
			: this(baseStream, new Aes(key, iv), true, closeOnDispose: closeOnDispose)
		{ }
		public BlockCryptoStream(string path, FileStreamOptions options, Aes aes, bool autoDisposeAes)
			: this(new FileStream(path, options), aes, autoDisposeAes, closeOnDispose: true)
		{ }
		public BlockCryptoStream(string path, FileStreamOptions options, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
			: this(path, options, new Aes(key, iv), true)
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
				EnsurePosition(value);
				_baseStream.Position = value;
				UpdCTR();
			}
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			var pos = _baseStream.Seek(offset, origin);
			EnsurePosition(pos);
			UpdCTR();
			return pos;
		}

		public override void SetLength(long value)
		{
			if (!Aes.IsValidSize(value))
			{
				throw new ArgumentException($"Length is not dividable by {nameof(Aes)} block size.", nameof(value));
			}
			if (value > Length)
			{
				throw new InvalidOperationException("Growing file without filling it is dangerous!");
			}
			_baseStream.SetLength(value);
			UpdCTR();
		}

		public override void Flush() => _baseStream.Flush();
		public override Task FlushAsync(CancellationToken cancellationToken) => _baseStream.FlushAsync(cancellationToken);

		public override int Read(Span<byte> buffer)
		{
			EnsureBuffer(buffer);
			var res = _baseStream.Read(buffer);
			_aes.Transform(buffer);
			return res;
		}
		public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
		public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			EnsureBuffer(buffer);
			var res = await _baseStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
			_aes.Transform(buffer.Span);
			return res;
		}
		public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			EnsureBuffer((ReadOnlySpan<byte>)buffer);
			var res = await _baseStream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
			_aes.Transform(buffer);
			return res;
		}
		public override void Write(ReadOnlySpan<byte> buffer)
		{
			EnsureBuffer(buffer);
			byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
			Span<byte> s_encryptedBuffer = sharedBuffer.AsSpan(0, buffer.Length);
			_aes.Transform(buffer, s_encryptedBuffer);
			_baseStream.Write(s_encryptedBuffer);
			ArrayPool<byte>.Shared.Return(sharedBuffer);
		}
		public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
		public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
		{
			EnsureBuffer(buffer);
			byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
			Memory<byte> m_sharedBuffer = sharedBuffer.AsMemory(0, buffer.Length);
			_aes.Transform(buffer.Span, m_sharedBuffer.Span);
			await _baseStream.WriteAsync(m_sharedBuffer, cancellationToken).ConfigureAwait(false);
			ArrayPool<byte>.Shared.Return(sharedBuffer);
		}

		/// <summary>
		/// Encrypt <paramref name="buffer"/> in-place and write it to stream.
		/// </summary>
		/// <param name="buffer"></param>
		public void WriteFast(Span<byte> buffer)
		{
			EnsureBuffer(buffer);
			_aes.Transform(buffer);
			_baseStream.Write(buffer);
		}
		/// <summary>
		/// Encrypt <paramref name="buffer"/> in-place and write it to stream asynchronously.
		/// </summary>
		/// <param name="buffer"></param>
		public ValueTask WriteFastAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			EnsureBuffer(buffer);
			_aes.Transform(buffer.Span);
			return _baseStream.WriteAsync(buffer, cancellationToken);
		}

		/// <summary>
		/// Read <paramref name="buffer"/> WITHOUT encryption.
		/// </summary>
		/// <param name="buffer"></param>
		public void ReadThroughEncryption(Span<byte> buffer)
		{
			EnsureBuffer(buffer);
			_baseStream.Read(buffer);
			UpdCTR();
		}
		/// <summary>
		/// Write <paramref name="buffer"/> WITHOUT encryption.
		/// </summary>
		/// <param name="buffer"></param>
		public void WriteThroughEncryption(ReadOnlySpan<byte> buffer)
		{
			EnsureBuffer(buffer);
			_baseStream.Write(buffer);
			UpdCTR();
		}
		public override int ReadByte() => throw new NotSupportedException();
		public override void WriteByte(byte value) => throw new NotSupportedException();

		private static void EnsurePosition(long pos,
			[CallerArgumentExpression("pos")] string pos_name = "")
		{
			if (!Aes.IsValidSize(pos))
			{
				throw new ArgumentException($"Position is not dividable by {nameof(Aes)} block size.", pos_name);
			}
		}
		private static void EnsureBuffer(ReadOnlySpan<byte> buffer,
			[CallerArgumentExpression("buffer")] string buffer_name = "")
		{
			if (!Aes.IsValidSize(buffer.Length))
			{
				throw new ArgumentException($"Length is not dividable by {nameof(Aes)} block size.", buffer_name);
			}
		}
		private static void EnsureBuffer(ReadOnlyMemory<byte> buffer,
			[CallerArgumentExpression("buffer")] string buffer_name = "")
		{
			if (!Aes.IsValidSize(buffer.Length))
			{
				throw new ArgumentException($"Length is not dividable by {nameof(Aes)} block size.", buffer_name);
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
