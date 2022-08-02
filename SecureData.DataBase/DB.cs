using System;
using System.Runtime.CompilerServices;
using System.Text;

using SecureData.Cryptography.Hash;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models;
using SecureData.DataBase.Models.Abstract;

using SecureData.DataBase.Helpers;

[assembly: InternalsVisibleTo("SecureData.Tests.DataBase")]

//TODO:0 zero out all on crash (static class thread-safe add sens buffers to it, zero out foreach on crash)

//TODO:5 cached filestream and make DB _buffer lower size (double caching is bad)

//TODO:9 gmac or hash?

namespace SecureData.DataBase;

//note: CNP = can be paralleled
public sealed class DB : IDisposable, IAsyncDisposable
{
	private static class HLayout
	{
		public const int HashSize = 32;
		public const int HashOffs = 0;

		public const int ArgonParamsSize = sizeof(uint) * 3; //time, memory, threads
		public const int ArgonParamsOffs = HashSize + HashOffs;

		public const int EncryptedKeySize = AesCtr.KeySize;
		public const int EncryptedKeyOffs = ArgonParamsOffs + ArgonParamsSize;

		public const int VersionSize = 16;
		public const int VersionOffs = EncryptedKeySize + EncryptedKeyOffs;

		public const int SaltSize = 16;
		public const int SaltOffs = VersionSize + VersionOffs;

		public const int LoginSize = 64;
		public const int LoginOffs = SaltSize + SaltOffs;

		public const int Size = LoginSize + LoginOffs;
		public const int HashStart = ArgonParamsOffs;
		public const int EncrStart = Size;
	}

	internal static class Consts
	{
		public const uint Version = 1;
		//should be greater than header and RNG size, and max IData size
		public const int InitBufferSize = 128 * 1024;

		public const int MinFileSize = HLayout.Size;

		public const int DataOffs = HLayout.Size;
	}

	private bool _isInited = false;

	private readonly byte[] _buffer = GC.AllocateUninitializedArray<byte>(Consts.InitBufferSize, false);
	private readonly AesCtr _mAes = new();
	private readonly FileStream _mFile;
	private readonly DataSet _dataSet = new();
	private readonly List<Data> _root = new();
	private readonly byte[] _hash = new byte[HLayout.HashSize];
	private readonly byte[] _salt = new byte[HLayout.SaltSize];

	private readonly ObjectPool<SHA256> _shaPool = new(4, () => new SHA256(), x => x.Initialize(), x => x.Dispose());

	public IReadOnlyList<Data> Root => _root;

	public string Login { get; private set; } = string.Empty;
	public uint Version { get; private set; } = 0;

	public DB(string path)
	{
		var fso = new FileStreamOptions()
		{
			Access = FileAccess.ReadWrite,
			BufferSize = 0,
			Options = FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.WriteThrough,
			Share = FileShare.None,
			Mode = FileMode.OpenOrCreate
		};
		_mFile = new FileStream(path, fso);
		var fileLength = _mFile.Length;
		if (fileLength > 0)
		{
			if (!AesCtr.IsValidSize(fileLength) || fileLength < Consts.MinFileSize)
			{
				throw DataBaseCorruptedException.WrongDBSize();
			}
		}
	}

	//TODO:0 cache on init = false
	public bool TryInit(string password)
	{
		EnsureNotInited();
		Span<byte> s_buffer = _buffer;
		_mFile.Position = 0;
		int firstReadBytes = _mFile.Read(s_buffer); //read header
		bool readAll = _mFile.EOF();
		Version = BinaryHelper.ReadUInt32(s_buffer.Slice(HLayout.VersionOffs, HLayout.VersionSize));
		if (Version != Consts.Version)
		{
			throw new DBVersionMismatchException(Version, Consts.Version);
		}
		BinaryHelper.ReadBytes(s_buffer.Slice(HLayout.HashOffs, HLayout.HashSize), _hash);
		BinaryHelper.ReadBytes(s_buffer.Slice(HLayout.SaltOffs, HLayout.SaltSize), _salt);
		Login = BinaryHelper.ReadString(s_buffer.Slice(HLayout.LoginOffs, HLayout.LoginSize));
		ReadOnlySpan<uint> argon2Params = MemoryHelper.As<uint>(s_buffer.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
		Span<byte> tmp = stackalloc byte[AesCtr.KeySize];
		Argon2d.ComputeHash(argon2Params[0], argon2Params[1], argon2Params[2],
			   MemoryHelper.AsBytes(password.AsSpan()), _salt, tmp);
		Span<byte> s_mKey = s_buffer.Slice(HLayout.EncryptedKeyOffs, HLayout.EncryptedKeyOffs);
		using (var tmpAes = new AesCtr(tmp, _salt))
		{
			tmpAes.Transform(s_mKey, 0);
		}
		_mAes.SetKeyIV(s_mKey, _salt);
		_mAes.Counter = 0;
		SHA256.ComputeHash(s_mKey, s_mKey);


		Data.Metadata metadata = new Data.Metadata();

		//TODO: clear dataSet and root on wrong key, or verify key before dataSet changes

		if (firstReadBytes < s_buffer.Length) //we read all bytes from file
		{
			s_buffer = s_buffer.Slice(0, firstReadBytes);
			_mAes.Transform(s_buffer.Slice(HLayout.EncrStart)); //decrypt data
			sha256.Transform(s_buffer.Slice(HLayout.HashStart)); //hash all from HashStart point
			sha256.Finalize(hash);
			if (!MemoryHelper.Compare(_hash, hash))
			{
				return false;
			}
			//TODO: here
			long pos = HLayout.Size;
			while (s_buffer.Length > 0)
			{
				if (metadata.TryCreate(s_buffer, out Data? data, out int readBytes))
				{
					_dataSet.AddOnInit(data,)
								}
			}
		}


		//data
		//int bytesRead = 0; //currently read bytes
		//int bytesProcessed = 0; //read and hashed bytes
		//ReadOnlySpan<byte> s_working = ReadOnlySpan<byte>.Empty;
		//long pos = _bcs.Position;
		//while ((bytesRead = _bcs.Read(s_buffer.Slice(bytesProcessed))) > 0)
		//{
		//	s_working = s_buffer.Slice(0, bytesRead);
		//	_sha.Transform(s_buffer.Slice(bytesProcessed, bytesRead - bytesProcessed)); //TODO: CBP
		//	while (s_working.Length >= Data.MinSizeToRead)
		//	{
		//		if (Data.TryCreateFromBuffer(s_working, out Data? data, out int readBytes))
		//		{
		//			_dataSet.Add(data, pos);
		//		}
		//		else if (readBytes == 0) //we dont get Data cauze not enough data in working buffer
		//		{
		//			bytesProcessed = s_working.Length; //dont read/hash this region again
		//			s_working.CopyTo(s_buffer); //copy for next iteration
		//			break;
		//		}
		//		s_working = s_working.Slice(readBytes);
		//		pos += readBytes;
		//	}
		//}
		//if (s_working.Length != 0)
		//{
		//	throw DataBaseCorruptedException.WrongDataItemsSize();
		//}
		//Data.OrganizeHierarchy(_dataSet, _root);

		//Span<byte> s_actualHash = s_buffer.Slice(0, SHA256.HashSize);
		//_sha.Finalize(s_actualHash);
		//_shaPool.Return(sha256);
		//if (!MemoryHelper.Compare(s_actualHash, _dbHeader.Hash.Span))
		//{
		//	return false;
		//}
		//_isInited = true;
		//return true;
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

		_mAes.SetKeyIV(key, salt);

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

	//TODO:8 setsensitive do not store all buffer

	//TODO:9 think about Arraypool instead of huge buffer? or mb custom class

	//TODO:6 aes, sha pool (bookmarks at creating new, also search for Clone() and CopyTo())
	public void LoadSensitive(Data data)
	{
		ReadOnlySpan<byte> s_encryptedCache;
		long cacheFilePos;
		if (!_dataSet.TryGetCache(data, out s_encryptedCache, out cacheFilePos))
		{
			Span<byte> s_emptyCache = _dataSet.CreateCache(data, out cacheFilePos);
			_mFile.Position = cacheFilePos;
			_mFile.Read(s_emptyCache);
			s_encryptedCache = s_emptyCache;
		}
		//TODO:9 do something with buffer (lock idk)
		uint ctr = AesCtr.ConvertToCTR(cacheFilePos);
		Span<byte> s_dataSensitive = _buffer.AsSpan(s_encryptedCache.Length);
		_mAes.Transform(s_encryptedCache, s_dataSensitive, ctr);
		data.LoadSensitive(s_dataSensitive);
	}

	public void Dispose()
	{
		foreach (var data in _dataSet)
		{
			//
		}
		_mAes.Dispose();
		_shaPool.Dispose();
		_bcs.Dispose();
	}

	public ValueTask DisposeAsync()
	{
		foreach (var data in _dataSet)
		{
			//TODO: zero mem
		}
		_mAes.Dispose();
		_shaPool.Dispose();
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
