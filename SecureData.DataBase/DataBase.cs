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

	private readonly Buffer _buffer = new(Consts.InitBufferSize);

	private readonly AesCtr _mAes = new();
	private readonly FileStream _mFile;
	private readonly DataSet _dataSet = new();
	private readonly byte[] _hash = new byte[HLayout.HashSize];
	private readonly byte[] _salt = new byte[HLayout.SaltSize];
	private readonly SHA256 _mHash = new();

	private readonly ObjectPool<SHA256> _shaPool = new(4, () => new SHA256(), x => x.Initialize(), x => x.Dispose());

	public IReadOnlyList<Data> Root => _dataSet.Root;

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
	}

	public void Create(string login, string password, Argon2dOptions passwordHashOptions)
	{
		EnsureNotInited();
		if (_mFile.Length != 0)
		{
			throw new InvalidOperationException("File not empty.");
		}
		try
		{
			Span<byte> header = _buffer.GetSpan(HLayout.Size);

			//init data
			MemoryHelper.RNG(_salt);
			Login = login;

			//hash password
			Span<byte> mKey = _buffer.GetSpan(AesCtr.KeySize);
			Argon2d.ComputeHash(passwordHashOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, mKey);
			_mAes.SetKeyIV(mKey, _salt);

			//write data to header buffer
			passwordHashOptions.Serialize(header.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
			BinaryHelper.Write(header.Slice(HLayout.VersionOffs, HLayout.VersionSize), Version);
			BinaryHelper.Write(header.Slice(HLayout.SaltOffs, HLayout.SaltSize), _salt);
			BinaryHelper.WriteStringWithRNG(header.Slice(HLayout.LoginOffs, HLayout.LoginSize), Login);

			//hash
			Span<byte> header_enc = _buffer.GetSpan(HLayout.Size - Consts.HashStart); //for encrypted header w/o hash
			_mAes.Transform(header.Slice(Consts.HashStart), header_enc, 0U);
			_mHash.Initialize();
			_mHash.Transform(header_enc);
			SHA256 sha = _shaPool.Rent();
			_mHash.CopyTo(sha);
			sha.Finalize(_hash);
			_shaPool.Return(sha);

			//write hash to header
			BinaryHelper.Write(header.Slice(HLayout.HashOffs, HLayout.HashSize), _hash);

			//write header to file
			_mFile.Write(header);

			FinishInit();
		}
		finally
		{
			_buffer.ReturnAll();
		}
	}
	public bool TryInit(string password)
	{
		EnsureNotInited();
		var fileLength = _mFile.Length;
		if (!AesCtr.IsValidSize(fileLength) || fileLength < Consts.MinFileSize)
		{
			throw DataBaseCorruptedException.WrongDBSize();
		}
		try
		{
			Span<byte> file = _buffer.GetSpan((int)fileLength);

			//read all file
			_mFile.Position = 0;
			_mFile.Read(file);

			//process header if not done yet
			if (Login == string.Empty)
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

			//init master aes
			Span<byte> mKey = _buffer.GetSpan(AesCtr.KeySize);
			Argon2dOptions argonOptions = new(file.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
			Argon2d.ComputeHash(argonOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, mKey);
			_mAes.SetKeyIV(mKey, _salt);

			//decrypt file data
			_mAes.Transform(file.Slice(Consts.HashStart), 0U);

			//check hash
			Span<byte> currentHash = _buffer.GetSpan(SHA256.HashSize);
			_mHash.Initialize();
			_mHash.Transform(file.Slice(Consts.HashStart));
			SHA256 sha = _shaPool.Rent();
			_mHash.CopyTo(sha);
			sha.Finalize(currentHash);
			_shaPool.Return(sha);
			if (!MemoryHelper.Compare(_hash, currentHash))
			{
				return false;
			}

			//read items
			Data.Metadata metadata = new();
			int filePos = Consts.DataOffs;
			ReadOnlySpan<byte> s_working = file.Slice(filePos);
			while (s_working.Length > 0)
			{
				Data? data = metadata.Create(s_working, currentHash, out int readBytes);
				if (data is not null)
				{
					_dataSet.AddOnInit(data, filePos);
				}
				s_working = s_working.Slice(readBytes);
				filePos += readBytes;
			}

			FinishInit();
			return true;
		}
		finally
		{
			_buffer.ReturnAll();
		}
	}

	public void AddData(Data data)
	{
		if(_dataSet.Contains(data.Id))
		{
			throw new InvalidOperationException("Data already added to database.");
		}
		data.FinishInit();
		_mFile.Position = _mFile.Length;
		_dataSet.Add(data, _mFile.Position);
		try
		{
			Span<byte> s_data = _buffer.GetSpan(data.Size);
			data.Flush(s_data); //flush data to buffer

			_mHash.Transform(s_data); //update master hash

			_mAes.Transform(s_data, GetCTRFromPos()); //encrypt

			_mFile.Write(s_data); //write data to file
		}
		finally
		{
			_buffer.ReturnAll();
		}
		SHA256 sha = _shaPool.Rent();
		_mHash.CopyTo(sha); //clone master hash
		sha.Finalize(_hash); //update hash in memory
		_shaPool.Return(sha);

		WriteCurrentHash(); //update hash in file
	}
	public void LoadSensitive(Data data)
	{
		if (!data.HasSensitive)
		{
			return;
		}
		_mFile.Position = _dataSet.GetFilePos(data) + data.SensitiveOffset;
		uint ctr = GetCTRFromPos();
		try
		{
			Span<byte> sensitive = _buffer.GetSpan(data.SensitiveSize);
			_mFile.ReadExactly(sensitive);
			_mAes.Transform(sensitive, ctr);
			data.LoadSensitive(sensitive);
		}
		finally
		{
			_buffer.ReturnAll();
		}
	}
	public void ModifyData<TData>(Action<TData> modifyAction)
	{

	}

	private void WriteCurrentHash()
	{
		_mFile.Position = HLayout.HashOffs;
		_mFile.Write(_hash);
	}
	private uint GetCTRFromPos() => AesCtr.ConvertToCTR(_mFile.Position - Consts.HashStart);

	private void FinishInit()
	{
		EnsureNotInited();
		_dataSet.FinishInit();
		_isInited = true;
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
