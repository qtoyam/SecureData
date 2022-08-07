using System.Runtime.CompilerServices;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.Storage.Exceptions;
using SecureData.Storage.Helpers;
using SecureData.Storage.Models.Abstract;
using SecureData.Storage.Services;

[assembly: InternalsVisibleTo("SecureData.Tests.Storage")]


//TODO:9 custom exceptions to hover mouse over method and see what it checks (for example: check for load / mutable etc)

//TODO:5 cached filestream

//TODO:0 wipe all on crash?

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

	private readonly Services.Buffer _buffer = new(Consts.InitBufferSize);

	private readonly AesCtr _mAes = new();
	private readonly FileStream _mFile;
	private readonly DataSet _dataSet = new();
	private readonly byte[] _hash = new byte[HLayout.HashSize];
	private readonly byte[] _salt = new byte[HLayout.SaltSize];
	private readonly SHA256 _mHash = new();

	private readonly ObjectPool<SHA256> _shaPool = new(4, () => new SHA256(), x => x.Initialize(), x => x.Dispose());

	public IReadOnlyList<Data> Root => _dataSet.Root;

	public string Login { get; private set; } = string.Empty;
	public static uint Version => Consts.Version;

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

		//init data
		MemoryHelper.RNG(_salt);
		Login = login;

		//hash password
		using (var rented_mKey = _buffer.Rent(AesCtr.KeySize))
		{
			Span<byte> mKey = rented_mKey.Span;
			Argon2d.ComputeHash(passwordHashOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, mKey);
			_mAes.SetKeyIV(mKey, _salt);
		}

		using (var rented_header = _buffer.Rent(HLayout.Size))
		{
			Span<byte> header = rented_header.Span;
			//write data to header buffer
			passwordHashOptions.Serialize(header.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
			BinaryHelper.Write(header.Slice(HLayout.VersionOffs, HLayout.VersionSize), Version);
			BinaryHelper.Write(header.Slice(HLayout.SaltOffs, HLayout.SaltSize), _salt);
			BinaryHelper.WriteStringWithRNG(header.Slice(HLayout.LoginOffs, HLayout.LoginSize), Login);

			//hash
			using (var rented_header_enc = _buffer.Rent(HLayout.Size - Consts.HashStart))
			{
				Span<byte> header_enc = rented_header_enc.Span; //for encrypted header w/o hash
				_mAes.Transform(header.Slice(Consts.HashStart), header_enc, GetCTRFromPos(Consts.HashStart));
				_mHash.Initialize();
				_mHash.Transform(header_enc);
			}
			using (var rented = _shaPool.Rent())
			{
				SHA256 sha = rented.Value;
				_mHash.CopyTo(sha);
				sha.Finalize(_hash);
			}

			//write hash to header
			BinaryHelper.Write(header.Slice(HLayout.HashOffs, HLayout.HashSize), _hash);

			//write header to file
			_mFile.Write(header);
		}

		FinishInit();
	}
	public bool TryInit(string password)
	{
		EnsureNotInited();
		var fileLength = _mFile.Length;
		if (!AesCtr.IsValidSize(fileLength) || fileLength < Consts.MinFileSize)
		{
			throw DataBaseCorruptedException.WrongDBSize();
		}
		_mFile.Position = 0;
		using (var rented_file = _buffer.Rent((int)fileLength))
		{
			Span<byte> file = rented_file.Span;

			//read all file
			_mFile.ReadExactly(file);

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
			using (var rented_mKey = _buffer.Rent(AesCtr.KeySize))
			{
				Span<byte> mKey = rented_mKey.Span;
				Argon2dOptions argonOptions = new(file.Slice(HLayout.ArgonParamsOffs, HLayout.ArgonParamsSize));
				Argon2d.ComputeHash(argonOptions, MemoryHelper.AsBytes(password.AsSpan()), _salt, mKey);
				_mAes.SetKeyIV(mKey, _salt);
			}

			//decrypt file data
			_mAes.Transform(file.Slice(Consts.HashStart), GetCTRFromPos(Consts.HashStart));

			//check hash
			using (var rented_currentHash = _buffer.Rent(SHA256.HashSize))
			{
				Span<byte> currentHash = rented_currentHash.Span;
				_mHash.Initialize();
				_mHash.Transform(file.Slice(Consts.HashStart));
				using (var rented = _shaPool.Rent())
				{
					SHA256 sha = rented.Value;
					_mHash.CopyTo(sha);
					sha.Finalize(currentHash);
				}
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
			}
		}

		FinishInit();
		return true;
	}

	public void AddData(Data data)
	{
		EnsureNewData(data);
		data.FinishInit();
		_mFile.Position = _mFile.Length;
		_dataSet.Add(data, _mFile.Position);
		using (var rented_dataBytes = _buffer.Rent(data.Size))
		{
			Span<byte> dataBytes = rented_dataBytes.Span;
			data.Flush(dataBytes); //flush data to buffer

			_mHash.Transform(dataBytes); //update master hash

			_mAes.Transform(dataBytes, GetCTRFromPos(_mFile.Position)); //encrypt

			_mFile.Write(dataBytes); //write data to file
		}

		ProcessMasterHash();
	}
	public void LoadSensitive(Data data)
	{
		EnsureContains(data);
		if (!data.HasSensitive || data.IsLoaded)
		{
			return;
		}
		_mFile.Position = _dataSet.GetFilePos(data) + data.SensitiveOffset;
		uint ctr = GetCTRFromPos(_mFile.Position);
		using (var rented_sensitiveBytes = _buffer.Rent(data.SensitiveSize))
		{
			Span<byte> sensitiveBytes = rented_sensitiveBytes.Span;
			_mFile.ReadExactly(sensitiveBytes);
			_mAes.Transform(sensitiveBytes, ctr);
			data.LoadSensitive(sensitiveBytes);
		}
	}
	public void ModifyData<TData>(TData data, Action<TData> modifyAction) where TData : Data
	{
		EnsureContains(data);
		data.Unfreeze();
		modifyAction(data);
		data.Freeze();

		if (data.HasChanges)
		{
			using (var rented_dataBytes = _buffer.Rent(data.Size))
			{
				Span<byte> dataBytes = rented_dataBytes.Span;
				data.Flush(dataBytes); //flush data to buffer

				_mFile.Position = _dataSet.GetFilePos(data); //set pos to write and get ctr from pos
				_mAes.Transform(dataBytes, GetCTRFromPos(_mFile.Position)); //encrypt

				_mFile.Write(dataBytes); //overwrite data to file
			}

			//update master hash
			_mFile.Position = Consts.HashStart;
			uint ctr = GetCTRFromPos(_mFile.Position);
			using (var rented_file_noHash = _buffer.Rent((int)(_mFile.Length - Consts.HashStart)))
			{
				Span<byte> file_noHash = rented_file_noHash.Span;
				_mFile.ReadExactly(file_noHash); //read file w/o hash
				_mAes.Transform(file_noHash, ctr); //decrypt all
				_mHash.Initialize(); //reset master hash
				_mHash.Transform(file_noHash); //hash file w/o hash
			}
			ProcessMasterHash();
		}
	}

	private void ProcessMasterHash()
	{
		using (var rented = _shaPool.Rent())
		{
			SHA256 sha = rented.Value;
			_mHash.CopyTo(sha);
			sha.Finalize(_hash);
		}

		_mFile.Position = HLayout.HashOffs;
		_mFile.Write(_hash);
	}
	private uint GetCTRFromPos(long pos) => AesCtr.ConvertToCTR(pos - Consts.HashStart);

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
	private void EnsureContains(Data data)
	{
		if (!_dataSet.Contains(data.Id))
		{
			throw new UnexpectedException($"Dataset does not contain data with id {data.Id}");
		}
	}
	private void EnsureNewData(Data data)
	{
		if (_dataSet.Contains(data.Id))
		{
			throw new UnexpectedException($"Dataset already contains data with id {data.Id}");
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
