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
			//should be greater than header and RNG size, and max IData size
			public const int InitBufferSize = 128 * 1024;
		}

		private bool _isInited = false;

		private readonly byte[] _buffer;
		private readonly DBHeader _dbHeader;
		private readonly AesCtr _aes; //not autodisposable
		private readonly BlockCryptoStream _bcs;
		private readonly SHA256 _sha; //TODO: sha thread-safe
		private readonly DataSet _dataSet;
		private readonly List<Data> _root;


		public IReadOnlyList<Data> Root => _root;

		public string Login => _dbHeader.Login;
		public uint Version => _dbHeader.Version;
		public ReadOnlySpan<byte> Hash => _dbHeader.Hash.Span;
		public ReadOnlySpan<byte> Salt => _dbHeader.Salt.Span;


		public DB(string path)
		{
			_buffer = new byte[Consts.InitBufferSize];
			_dbHeader = new DBHeader();
			_aes = new AesCtr();
			var fso = new FileStreamOptions()
			{
				Access = FileAccess.ReadWrite,
				BufferSize = 0,
				Options = FileOptions.Asynchronous | FileOptions.RandomAccess,
				Share = FileShare.None,
				Mode = FileMode.OpenOrCreate
			};
			_bcs = new BlockCryptoStream(path, fso, _aes, false);
			_sha = new SHA256();
			_dataSet = new();
			_root = new List<Data>();
		}

		public bool TryInit(ReadOnlySpan<byte> key)
		{
			EnsureNotInited();
			try
			{
				_bcs.Position = 0;
				_sha.Initialize();
				Span<byte> s_buffer = _buffer;

				//header
				if (!_dbHeader.IsInited)
				{
					_bcs.ReadThroughEncryption(_dbHeader.RawMemory.Span);
					_dbHeader.Update();
					_sha.Transform(_dbHeader.GetRawHashable());
					_aes.SetIV(_dbHeader.Salt.Span);
				}
				_aes.SetKey(key);
				//update hash with header's RNG
				{
					Span<byte> s_rng = s_buffer.Slice(0, DBHeader.Layout.RNGSize);
					_bcs.Read(s_rng);
					_sha.Transform(s_rng);
				}

				//data
				int bytesRead = 0; //currently read bytes
				int bytesProcessed = 0; //read and hashed bytes
				ReadOnlySpan<byte> s_working = ReadOnlySpan<byte>.Empty;
				long pos = _bcs.Position;
				while ((bytesRead = _bcs.Read(s_buffer.Slice(bytesProcessed))) > 0)
				{
					s_working = s_buffer.Slice(0, bytesRead);
					_sha.Transform(s_buffer.Slice(bytesProcessed, bytesRead - bytesProcessed)); //TODO: CBP
					while (s_working.Length >= Data.MinSizeToRead)
					{
						if (Data.TryCreateFromBuffer(s_working, out Data? data, out int readBytes))
						{
							_dataSet.Add(data, pos);
						}
						else if (readBytes == 0) //we dont get Data cauze not enough data in working buffer
						{
							bytesProcessed = s_working.Length; //dont read/hash this region again
							s_working.CopyTo(s_buffer); //copy for next iteration
							break;
						}
						s_working = s_working.Slice(readBytes);
						pos += readBytes;
					}
				}
				if (s_working.Length != 0)
				{
					throw DataBaseCorruptedException.WrongDataItemsSize();
				}
				Data.OrganizeHierarchy(_dataSet, _root);

				Span<byte> s_actualHash = s_buffer.Slice(0, SHA256.HashSize);
				_sha.Finalize(s_actualHash);
				if (!MemoryHelper.Compare(s_actualHash, _dbHeader.Hash.Span))
				{
					return false;
				}
				_isInited = true;
				return true;
			}
			finally
			{
				MemoryHelper.ZeroOut(_buffer);
			}
		}

		public void Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, string login)
		{
			if (_bcs.Length != 0)
			{
				throw new InvalidOperationException("File not empty.");
			}
			EnsureNotInited();
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
				Span<byte> s_headerRNG = s_buffer.Slice(0, DBHeader.Layout.RNGSize);
				MemoryHelper.RNG(s_headerRNG);
				_sha.Transform(s_headerRNG); //hash RNG
				_bcs.WriteFast(s_headerRNG);
			}
			_sha.Finalize(_dbHeader.Hash.Span); //finalize hash directly to Header
			WriteCurrentHash();
			_isInited = true;
			//note: buffer contains encrypted RNG, so no need to ZeroOut it.
		}

		public void AddData(Data data)
		{
			Span<byte> s_buffer = _buffer;
			try
			{
				_sha.Initialize();
				ComputeHash(_sha);
				//check hash
				{
					Span<byte> s_actualHash = s_buffer.Slice(0, _dbHeader.Hash.Length);
					using (SHA256 shaTmp = _sha.Clone())
					{
						shaTmp.Finalize(s_actualHash);
					}
					if (!MemoryHelper.Compare(_dbHeader.Hash.Span, s_actualHash))
					{
						throw DataBaseCorruptedException.UnexpectedHash();
					}
				}
				data.FinishInit();
				if (data.HasParent)
				{
					data.Parent.Add(data);
				}
				else
				{
					_root.Add(data);
				}
				_dataSet.Add(data, _bcs.Position);
				Span<byte> s_data = s_buffer.Slice(0, data.Size);
				data.Flush(s_data); //flush data to buffer
				_sha.Transform(s_data); //hash it
				_bcs.WriteFast(s_data); //write it
				_sha.Finalize(_dbHeader.Hash.Span); //update hash in memory
				WriteCurrentHash(); //update hash in DB
			}
			finally
			{
				MemoryHelper.ZeroOut(s_buffer);
			}
		}

		private void WriteCurrentHash()
		{
			_bcs.Position = DBHeader.Layout.HashOffset;
			_bcs.WriteThroughEncryption(_dbHeader.Hash.Span);
		}

		private void ComputeHash(SHA256 sha)
		{
			_bcs.Position = DBHeader.HashStart;
			Span<byte> s_buffer = _buffer;
			{
				Span<byte> s_header = s_buffer.Slice(0, DBHeader.Size - DBHeader.HashStart);
				_bcs.ReadThroughEncryption(s_header);
				sha.Transform(s_header);
			}
			int bytesRead;
			while ((bytesRead = _bcs.Read(s_buffer)) > 0)
			{
				sha.Transform(s_buffer.Slice(0, bytesRead));
			}
		}

		//TODO:10 test bcs with random actions over MemoryStream

		//TODO:8 setsensitive do not store all buffer

		//TODO:9 think about Arraypool instead of huge buffer? or mb custom class

		//TODO:6 aes, sha pool (bookmarks at creating new, also search for Clone() and CopyTo())
		public void LoadSensitive(Data data)
		{
			if (!data.HasSensitiveContent)
			{
				return;
			}
			ReadOnlyMemory<byte>? cache;
			if (!_dataSet.TryGetCache(data, out cache))
			{
				
			}
		}

		public void Dispose()
		{
			foreach (var data in _dataSet)
			{
				//
			}
			_aes.Dispose();
			_bcs.Dispose();
		}

		public ValueTask DisposeAsync()
		{
			foreach (var data in _dataSet)
			{
				//TODO: zero mem
			}
			_aes.Dispose();
			return _bcs.DisposeAsync();
		}

		private void EnsureNotInited()
		{
			if (_isInited)
			{
				throw new InvalidOperationException("DB is already initialized.");
			}
		}
	}
}
