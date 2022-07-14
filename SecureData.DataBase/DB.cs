using System;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;
using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase
{
	//note: CNP = can be paralleled
	public sealed class DB : IDisposable, IAsyncDisposable
	{
		//TODO: default value

		private static uint _id = Consts.ReservedId;
		internal static uint GetId()
		{
			return Interlocked.Add(ref _id, 1);
		}

		internal static class Consts
		{
			public const uint Version = 1;
			public const uint ReservedId = 0;
			//should be greater than DBHeader real size and max IData size
			public const int InitBufferSize = 128 * 1024;
		}

		private readonly byte[] _buffer;
		private readonly DBHeader _dbHeader;
		private readonly Aes _aes; //not autodisposable
		private readonly BlockCryptoStream _bcs;
		private readonly SHA256 _sha256;
		private readonly Dictionary<uint, Data> _data;

		public string Login => _dbHeader.Login;
		public uint Version => _dbHeader.Version;
		public ReadOnlyMemory<byte> Hash => _dbHeader.Hash;
		public ReadOnlyMemory<byte> Salt => _dbHeader.Salt;

		//private readonly ReadOnlyDictionary<uint, IData> _items;
		//public ReadOnlyDictionary<uint, IData> Items => _items;

		public DB(string path, bool create)
		{
			_buffer = new byte[Consts.InitBufferSize];
			_dbHeader = new DBHeader();
			_aes = new Aes();
			var fso = new FileStreamOptions()
			{
				Access = FileAccess.ReadWrite,
				BufferSize = 0,
				Options = FileOptions.Asynchronous | FileOptions.RandomAccess,
				Share = FileShare.None,
				Mode = create ? FileMode.CreateNew : FileMode.Open
			};
			_bcs = new BlockCryptoStream(path, fso, _aes, false);
			_sha256 = new SHA256();
			_data = new Dictionary<uint, Data>();
		}

		//TODO: do not init again, check it
		public bool TryInit(ReadOnlySpan<byte> key)
		{
			try
			{
				_bcs.Position = 0;
				_sha256.Initialize();
				Span<byte> s_buffer = _buffer;

				//header
				_bcs.ReadThroughEncryption(_dbHeader.RawMemory.Span); //TODO: do not read again if new key, iv supplied
				_dbHeader.Update();
				_sha256.Transform(_dbHeader.GetRawHashable());
				_aes.SetKeyIV(key, _dbHeader.Salt.Span);
				Span<byte> s_rng = s_buffer.Slice(0, _dbHeader.RNGSize);
				_bcs.Read(s_rng);
				_sha256.Transform(s_rng);


				//data
				int bytesRead = 0; //currently read bytes
				int bytesProcessed = 0; //read and hashed bytes
				while ((bytesRead = _bcs.Read(s_buffer.Slice(bytesProcessed))) > 0)
				{
					_sha256.Transform(s_buffer.Slice(bytesProcessed, bytesRead - bytesProcessed)); //TODO: CBP
					int readTo = _bcs.EOF() ? 1 : LayoutBase.MaxDataSize; //1 to loop while >= 1 instead of >= 0 (can be runned when == 0)
					ReadOnlySpan<byte> s_working = s_buffer.Slice(0, bytesRead);
					while (s_working.Length >= readTo)
					{
						Data d = Data.Create(s_working);
						if (d.Id > _id)
						{
							_id = d.Id;
						}
						if (!d.IsDeleted())
						{
							_data.Add(d.Id, d);
						}
						s_working = s_working.Slice(d.Size);
					}
					if (s_working.Length != 0)
					{
						// will throw in Data.Create if readTo == 0
						bytesProcessed = s_working.Length; //dont read/hash this region again
						s_working.CopyTo(s_buffer); //copy for next iteration
					}
				}
				Data.OrganizeHierarchy(_data); //TODO: CBP

				Span<byte> s_actualHash = s_buffer.Slice(0, SHA256.HashSize);
				_sha256.Finalize(s_actualHash);
				if (!MemoryHelper.Compare(s_actualHash, _dbHeader.Hash.Span))
				{
					return false;
				}

				return true;
			}
			finally
			{
				MemoryHelper.ZeroOut(_buffer);
			}
		}

		public void Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, string login)
		{
			_bcs.Position = 0;
			_sha256.Initialize();
			Span<byte> s_buffer = _buffer;

			_aes.SetKeyIV(key, salt);

			//header (update hash in the end)
			_dbHeader.Login = login;
			_dbHeader.Version = Consts.Version;
			BinaryHelper.Write(_dbHeader.Salt.Span, salt);
			_dbHeader.Flush();

			_sha256.Transform(_dbHeader.GetRawHashable()); //hash Header
			_bcs.WriteThroughEncryption(_dbHeader.RawMemory.Span);
			//rng
			{
				Span<byte> s_headerRNG = s_buffer.Slice(0, _dbHeader.RNGSize);
				MemoryHelper.RNG(s_headerRNG);
				_sha256.Transform(s_headerRNG); //hash RNG
				_bcs.WriteFast(s_headerRNG);
			}
			_sha256.Finalize(_dbHeader.Hash.Span); //finalize hash directly to Header
			UpdateHash();
			//note: buffer contains encrypted RNG, so no need to ZeroOut it.
		}

		//private void UpdateHashHeader()
		//{
		//	_sha256.Transform(_dbHeader.GetRawHashable());
		//	_bcs.Position = _dbHeader.RNGOffset;
		//	Span<byte> s_rng = _buffer.AsSpan(0, _dbHeader.RNGSize);
		//	_bcs.Read(s_rng);
		//	_sha256.Transform(s_rng);
		//}
		/// <summary>
		/// Consumes first <see cref="SHA256.HashSize"/> bytes of <see cref="_buffer"/>.
		/// </summary>
		private void UpdateHash()
		{
			_bcs.Position = DBHeader.Layout.HashOffset;
			_bcs.WriteThroughEncryption(_dbHeader.Hash.Span);
		}

		public void Dispose()
		{
			_aes.Dispose();
			_bcs.Dispose();
		}

		public ValueTask DisposeAsync()
		{
			_aes.Dispose();
			return _bcs.DisposeAsync();
		}
	}
}
