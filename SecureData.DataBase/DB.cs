using System;
using System.Runtime.CompilerServices;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models;
using SecureData.DataBase.Models.Abstract;

[assembly: InternalsVisibleTo("SecureData.Tests.DataBase")]

namespace SecureData.DataBase
{
	//note: CNP = can be paralleled
	public sealed class DB : IDisposable, IAsyncDisposable
	{
		internal static class Consts
		{
			public const uint Version = 1;
			//should be greater than DBHeader real size and max IData size
			public const int InitBufferSize = 128 * 1024;
		}

		private readonly byte[] _buffer;
		private readonly DBHeader _dbHeader;
		private readonly Aes _aes; //not autodisposable
		private readonly BlockCryptoStream _bcs;
		private readonly SHA256 _sha; //TODO: sha thread-safe
		private readonly Dictionary<uint, Data> _allData;
		private readonly List<Data> _root;

		public IReadOnlyList<Data> Root => _root;

		public string Login => _dbHeader.Login;
		public uint Version => _dbHeader.Version;
		public ReadOnlySpan<byte> Hash => _dbHeader.Hash.Span;
		public ReadOnlySpan<byte> Salt => _dbHeader.Salt.Span;


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
			_sha = new SHA256();
			_allData = new Dictionary<uint, Data>();
			_root = new List<Data>();
		}

		//TODO: do not init again, check it
		public bool TryInit(ReadOnlySpan<byte> key)
		{
			try
			{
				_bcs.Position = 0;
				_sha.Initialize();
				Span<byte> s_buffer = _buffer;

				//header
				if (!_dbHeader.IsInited)
				{
					_bcs.ReadThroughEncryption(_dbHeader.RawMemory.Span); //TODO: do not read again if new key, iv supplied
					_dbHeader.Update();
					_sha.Transform(_dbHeader.GetRawHashable());
					_aes.SetIV(_dbHeader.Salt.Span);
				}
				_aes.SetKey(key);
				ComputeRNGHash(_sha);


				//data
				int bytesRead = 0; //currently read bytes
				int bytesProcessed = 0; //read and hashed bytes
				ReadOnlySpan<byte> s_working = ReadOnlySpan<byte>.Empty;
				while ((bytesRead = _bcs.Read(s_buffer.Slice(bytesProcessed))) > 0)
				{
					s_working = s_buffer.Slice(0, bytesRead);
					_sha.Transform(s_buffer.Slice(bytesProcessed, bytesRead - bytesProcessed)); //TODO: CBP
					while (s_working.Length >= Data.MinSizeToFindDataType)
					{
						if (Data.TryCreateFromBuffer(s_working, out Data? data, out int readBytes))
						{
							_allData.Add(data.Id, data);
						}
						else if (readBytes == 0) //we dont get Data cauze not enough data in working buffer
						{
							bytesProcessed = s_working.Length; //dont read/hash this region again
							s_working.CopyTo(s_buffer); //copy for next iteration
							break;
						}
						s_working = s_working.Slice(readBytes);
					}
				}
				if(s_working.Length != 0)
				{
					throw DataBaseCorruptedException.WrongDataItemsSize();
				}
				Data.OrganizeHierarchy(_allData, _root);

				Span<byte> s_actualHash = s_buffer.Slice(0, SHA256.HashSize);
				_sha.Finalize(s_actualHash);
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
			_sha.Initialize();
			Span<byte> s_buffer = _buffer;

			_aes.SetKeyIV(key, salt);

			//header (update hash in the end)
			_dbHeader.Login = login;
			_dbHeader.Version = Consts.Version;
			BinaryHelper.Write(_dbHeader.Salt.Span, salt);
			_dbHeader.Flush();

			_sha.Transform(_dbHeader.GetRawHashable()); //hash Header
			_bcs.WriteThroughEncryption(_dbHeader.RawMemory.Span);
			//rng
			{
				Span<byte> s_headerRNG = s_buffer.Slice(0, _dbHeader.RNGSize);
				MemoryHelper.RNG(s_headerRNG);
				_sha.Transform(s_headerRNG); //hash RNG
				_bcs.WriteFast(s_headerRNG);
			}
			_sha.Finalize(_dbHeader.Hash.Span); //finalize hash directly to Header
			WriteCurrentHash();
			//note: buffer contains encrypted RNG, so no need to ZeroOut it.
		}

		public void AddData(Data data)
		{
			try
			{
				_sha.Initialize();
				//hash header
				_sha.Transform(_dbHeader.GetRawHashable());
				ComputeRNGHash(_sha);
				ComputeDataHash(_sha);
				//check hash
				{
					Span<byte> s_actualHash = _buffer.AsSpan(0, SHA256.HashSize);
					using (SHA256 shaTmp = _sha.Clone())
					{
						shaTmp.Finalize(s_actualHash);
					}
					if (!MemoryHelper.Compare(_dbHeader.Hash.Span, s_actualHash))
					{
						throw DataBaseCorruptedException.UnexpectedHash();
					}
				}
				data.InitNew();
				WriteNewData(data, _sha);
				_allData.Add(data.Id, data);
				if (data.Parent is null)
				{
					_root.Add(data);
				}
				_sha.Finalize(_dbHeader.Hash.Span);
				WriteCurrentHash();
			}
			finally
			{
				MemoryHelper.ZeroOut(_buffer);
			}

		}

		private void WriteCurrentHash()
		{
			_bcs.Position = DBHeader.Layout.HashOffset;
			_bcs.WriteThroughEncryption(_dbHeader.Hash.Span);
		}
		/// <summary>
		/// Reads RNG from <see cref="_bcs"/> and computes hash.
		/// Consumes first RNGSize's bytes from <see cref="_buffer"/>.
		/// MUST be zero-out.
		/// </summary>
		private void ComputeRNGHash(SHA256 sha)
		{
			_bcs.Position = _dbHeader.RNGOffset;
			Span<byte> s_rng = _buffer.AsSpan(0, _dbHeader.RNGSize);
			_bcs.Read(s_rng);
			sha.Transform(s_rng);
		}
		/// <summary>
		/// Reads all data from <see cref="_bcs"/> and computes hash.
		/// Can consume full <see cref="_buffer"/>.
		/// MUST be zero-out.
		/// </summary>
		/// <param name="sha"></param>
		private void ComputeDataHash(SHA256 sha)
		{
			_bcs.Position = _dbHeader.DBSize;
			Span<byte> s_buffer = _buffer;
			int bytesRead;
			while ((bytesRead = _bcs.Read(s_buffer)) > 0)
			{
				sha.Transform(s_buffer.Slice(0, bytesRead));
			}
		}

		/// <summary>
		/// Consumes up to <see cref="Data.MaxSize"/> bytes of <see cref="_buffer"/>.
		/// </summary>
		private void WriteNewData(Data data, SHA256 sha)
		{
			_bcs.Seek(0, SeekOrigin.End);
			Span<byte> s_dataLocked = _buffer.AsSpan(0, data.Size);
			data.LockMeTemp(s_dataLocked);
			sha.Transform(s_dataLocked);
			_bcs.WriteFast(s_dataLocked);
		}

		public void Dispose()
		{
			foreach(var data in _allData.Values)
			{
				data.Clear();
			}
			_aes.Dispose();
			_bcs.Dispose();
		}

		public ValueTask DisposeAsync()
		{
			foreach (var data in _allData.Values)
			{
				data.Clear();
			}
			_aes.Dispose();
			return _bcs.DisposeAsync();
		}
	}
}
