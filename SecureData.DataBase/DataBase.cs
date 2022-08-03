using System;
using System.Runtime.CompilerServices;
using System.Text;

using SecureData.Cryptography.Hash;
using SecureData.Storage.Exceptions;
using SecureData.Storage.Helpers;
using SecureData.Storage.Models;
using SecureData.Storage.Models.Abstract;

using SecureData.Cryptography.SymmetricEncryption;

[assembly: InternalsVisibleTo("SecureData.Tests.Storage")]

//TODO:0 wipe all on crash?

//TODO:5 cached filestream

namespace SecureData.Storage;

public sealed class DataBase : IDisposable, IAsyncDisposable
{
	private static class HLayout
	{
		public const int HashSize = 32;
		public const int HashOffs = 0;

		public const int ArgonParamsSize = sizeof(uint) * 3; //time, memory, threads
		public const int ArgonParamsOffs = HashSize + HashOffs;

		public const int VersionSize = sizeof(uint);
		public const int VersionOffs = ArgonParamsSize + ArgonParamsOffs;

		public const int SaltSize = 16;
		public const int SaltOffs = VersionSize + VersionOffs;

		public const int LoginSize = 64;
		public const int LoginOffs = SaltSize + SaltOffs;

		public const int Size = LoginSize + LoginOffs;

	}

	internal static class Consts
	{
		public const uint Version = 1;
		//should be greater than header and RNG size, and max IData size
		public const int InitBufferSize = 128 * 1024;

		public const int MinFileSize = HLayout.Size;

		public const int DataOffs = HLayout.Size;

		public const int HashStart = HLayout.ArgonParamsOffs;
		public const int EncrStart = DataOffs;
	}

	private bool _isInited = false;

	private byte[]? _buffer = GC.AllocateUninitializedArray<byte>(Consts.InitBufferSize, false);
	private byte[] Buffer => _buffer ??= GC.AllocateUninitializedArray<byte>(Consts.InitBufferSize, false);

	private readonly AesCtr _mAes = new();
	private readonly FileStream _mFile;
	private readonly DataSet _dataSet = new();
	private readonly List<Data> _root = new();
	private readonly byte[] _hash = new byte[HLayout.HashSize];
	private readonly byte[] _salt = new byte[HLayout.SaltSize];
	private readonly SHA256 _mHash = new();

	private readonly ObjectPool<SHA256> _shaPool = new(4, () => new SHA256(), x => x.Initialize(), x => x.Dispose());

	public IReadOnlyList<Data> Root => _root;

	public string Login { get; private set; } = string.Empty;
	public uint Version => Consts.Version;

	public DataBase(string path)
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

	public bool TryInit(string password)
	{
		EnsureNotInited();

		Span<byte> file = _mFile.Length > Buffer.Length ?
			new byte[_mFile.Length] :
			Buffer.AsSpan(0, (int)_mFile.Length);

		//read all file
		_mFile.Position = 0;
		_mFile.Read(file);

		//process header if not done yet
		if (Login != string.Empty)
		{
			uint dbVersion = BinaryHelper.ReadUInt32(file.Slice(HLayout.VersionOffs, HLayout.VersionSize));
			if (dbVersion != Version)
			{
				throw new DBVersionMismatchException(dbVersion, Version);
			}
			BinaryHelper.ReadBytes(file.Slice(HLayout.HashOffs, HLayout.HashSize), _hash);
			BinaryHelper.ReadBytes(file.Slice(HLayout.SaltOffs, HLayout.SaltSize), _salt);
			Login = BinaryHelper.ReadString(file.Slice(HLayout.LoginOffs, HLayout.LoginSize));
		}

		Span<byte> tmp = stackalloc byte[AesCtr.KeySize];

		//init master aes
		Span<byte> s_mKey = tmp.Slice(0, AesCtr.KeySize);
		Argon2dOptions argonOptions = new(file.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
		Argon2d.ComputeHash(argonOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, tmp);
		_mAes.SetKeyIV(tmp, _salt);

		//decrypt file data
		_mAes.Transform(file.Slice(Consts.HashStart), 0U);

		//check hash
		Span<byte> s_actHash = tmp.Slice(0, SHA256.HashSize);
		_mHash.Initialize();
		_mHash.Transform(file.Slice(Consts.HashStart));
		SHA256 sha = _shaPool.Rent();
		_mHash.CopyTo(sha);
		sha.Finalize(s_actHash);
		_shaPool.Return(sha);
		if (!MemoryHelper.Compare(_hash, s_actHash))
		{
			return false;
		}

		//read items
		Data.Metadata metadata = new();
		int filePos = Consts.DataOffs;
		ReadOnlySpan<byte> s_working = file.Slice(filePos);
		while (s_working.Length > 0)
		{
			Data? data = metadata.Create(s_working, tmp, out int readBytes);
			if (data is not null)
			{
				_dataSet.AddOnInit(data, filePos);
			}
			s_working = s_working.Slice(readBytes);
			filePos += readBytes;
		}
		_isInited = true;
		return true;
	}

	public void Create(string login, string password, Argon2dOptions passwordHashOptions)
	{
		EnsureNotInited();
		if (_mFile.Length != 0)
		{
			throw new InvalidOperationException("File not empty.");
		}

		Span<byte> header = Buffer.AsSpan(0, HLayout.Size);

		//init data
		MemoryHelper.RNG(_salt);
		Login = login;

		//hash password
		Span<byte> s_mKey = header.Slice(0, AesCtr.KeySize); //will be overwritten so no need to wipe
		Argon2d.ComputeHash(passwordHashOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, s_mKey);
		_mAes.SetKeyIV(s_mKey, _salt);

		//write data to header buffer
		passwordHashOptions.Serialize(header.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
		BinaryHelper.Write(header.Slice(HLayout.VersionOffs, HLayout.VersionSize), Version);
		BinaryHelper.Write(header.Slice(HLayout.SaltOffs, HLayout.SaltSize), _salt);
		BinaryHelper.WriteStringWithRNG(header.Slice(HLayout.LoginOffs, HLayout.LoginSize), Login);

		//hash
		Span<byte> header_enc = Buffer.AsSpan(header.Length, HLayout.Size - Consts.HashStart); //for encrypted header w/o hash
		_mAes.Transform(header.Slice(Consts.HashStart), header_enc, 0U);
		SHA256.ComputeHash(header_enc, header.Slice(HLayout.HashOffs, HLayout.HashSize));

		//write header
		_mFile.Write(header);

		_isInited = true;
	}

	//TODO:9 get bytes from _buffer simplify (mb class that counts and method clear that frees all)

	public void AddData(Data data)
	{
		data.FinishInit();
		_dataSet.Add(data, _mFile.Length);
		Span<byte> s_data = Buffer.AsSpan(0, data.Size);
		data.Flush(s_data); //flush data to buffer
		_mHash.Transform(s_data); //update master hash
		_mAes.Transform(s_data, AesCtr.ConvertToCTR(_mFile.Length)); //encrypt
		_mFile.Position = 0;
		_mFile.Write(s_data); //write data to file
		SHA256 sha = _shaPool.Rent();
		_mHash.CopyTo(sha); //clone master hash
		sha.Finalize(_hash); //update hash in memory
		_shaPool.Return(sha);
		WriteCurrentHash(); //update hash in file

		//TODO:9 mb finalize without copy?
	}

	private void WriteCurrentHash()
	{
		_mFile.Position = HLayout.HashOffs;
		_mFile.Write(_hash);
	}


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
		Span<byte> s_dataSensitive = Buffer.AsSpan(s_encryptedCache.Length);
		_mAes.Transform(s_encryptedCache, s_dataSensitive, ctr);
		data.LoadSensitive(s_dataSensitive);
	}
	private void EnsureNotInited()
	{
		if (_isInited)
		{
			throw new InvalidOperationException("DB is already initialized.");
		}
	}

	public ValueTask DisposeAsync()
	{
		_mAes.Dispose();
		foreach (var data in _dataSet)
		{
			data.ClearSensitive();
		}
		_shaPool.Dispose();
		_mHash.Dispose();
		return _mFile.DisposeAsync();
	}
	public void Dispose()
	{
		_mAes.Dispose();
		foreach (var data in _dataSet)
		{
			data.ClearSensitive();
		}
		_shaPool.Dispose();
		_mHash.Dispose();
		_mFile.Dispose();
	}
}
