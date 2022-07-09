using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;
using SecureData.DataBase.ModelsIO;

//TODO: ValueTask ? Task

namespace SecureData.DataBase
{
	public sealed class DB : IDisposable, IAsyncDisposable
	{
		//TODO: default value
		private static uint _id;
		internal static uint GetId()
		{
			return Interlocked.Add(ref _id, 1);
		}

		private static class Consts
		{
			public const uint Version = 1;
			//should be greater than DBHeader real size and max IData size
			public const int InitBufferSize = 128 * 1024;
		}

		private readonly byte[] _buffer;
#if DEBUG//for tests
		public
#else
		private 
#endif
		readonly DBHeader _header;
		private readonly Aes256Ctr _aes; //not autodisposable
		private readonly BlockCryptoStream _bcs;
		private readonly SHA256 _sha256;
		private readonly Dictionary<uint, IData> _data;

		//private readonly ReadOnlyDictionary<uint, IData> _items;
		//public ReadOnlyDictionary<uint, IData> Items => _items;

		private DB(byte[] buffer, DBHeader dbHeader, Aes256Ctr aes, BlockCryptoStream bcs, SHA256 sha256, Dictionary<uint, IData> data)
		{
			_buffer = buffer;
			_header = dbHeader;
			_aes = aes;
			_bcs = bcs;
			_sha256 = sha256;
			_data = data;
			//_items = new(_data);
		}
		private DB(byte[] buffer, DBHeader dbHeader, Aes256Ctr aes, BlockCryptoStream bcs, SHA256 sha256)
			:this(buffer, dbHeader, aes, bcs, sha256, new Dictionary<uint, IData>()) { }

		public static DB Init(string path, ReadOnlySpan<byte> key)
		{
			//to be inited
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;
			SHA256? sha256 = null;

			DBHeader dbHeader = new();
			Dictionary<uint, IData> data;
			byte[] buffer = new byte[Consts.InitBufferSize];
			try
			{
				Span<byte> s_buffer = buffer;
				sha256 = new SHA256();

				//read, create and hash dbheader
				Span<byte> s_dbHeader = dbHeader.GetRaw();
				using (var f = new FileStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.Read,
					Mode = FileMode.Open, //will throw if no file
					BufferSize = 0, //no buffering
					Options = FileOptions.SequentialScan
				}))
				{
					f.Read(s_dbHeader);
				}
				DBHeaderIO.ComputeHash(s_dbHeader, sha256);

				//create main BlockCryptoStream
				aes = new Aes256Ctr(key, DBHeader.GetSalt(s_dbHeader));
				bcs = new BlockCryptoStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.ReadWrite,
					BufferSize = 0, //no buffering
					Mode = FileMode.Open,
					Options = FileOptions.RandomAccess | FileOptions.Asynchronous
				}, aes, false);

				//hash RNG in dbheader
				DBHeaderIO.ComputeRNGHash(bcs, s_buffer, sha256);

				//read and hash items
				data = DataIO.ReadAllIData(bcs, s_buffer, sha256);
				Span<byte> s_actualHash = s_buffer.Slice(0, DBHeader.Layout.HashSize);
				sha256.Finalize(s_actualHash);
				if (!MemoryHelper.Compare(s_actualHash, DBHeader.GetHash(s_dbHeader)))
				{
					throw new DataBaseWrongHashException();
				}
				//TODO: parallel organize data
				DataHelper.OrganizeFolders(data);

				sha256.Initialize();
				return new DB(buffer, dbHeader, aes, bcs, sha256, data);
			}
			catch
			{
				bcs?.Dispose();
				aes?.Dispose();
				sha256?.Dispose();
				throw;
			}
			finally
			{
				MemoryHelper.ZeroOut(buffer);
			}
		}

		public static DB Create(string path, ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt, string login)
		{
			//to be created
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;
			SHA256? sha256 = null;

			DBHeader dbHeader = new();
			byte[] buffer = new byte[Consts.InitBufferSize];
			try
			{
				Span<byte> s_buffer = buffer;
				sha256 = new SHA256();
				aes = new Aes256Ctr(key, salt);
				bcs = new BlockCryptoStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.Write,
					BufferSize = 0, //no buffering
					Mode = FileMode.CreateNew,
					Options = FileOptions.RandomAccess | FileOptions.Asynchronous
				}, aes, false);

				Span<byte> s_dbHeader = dbHeader.GetRaw();

				dbHeader.Init(s_dbHeader, Consts.Version, salt, login); //set values

				DBHeaderIO.ComputeHash(s_dbHeader, sha256); //hash dbheader
				DBHeaderIO.Write(bcs, s_dbHeader);
				DBHeaderIO.FillRNG(bcs, s_buffer, sha256); //write rng to bcs

				Span<byte> s_dbHeader_Hash = DBHeader.GetHash(s_dbHeader);
				sha256.Finalize(s_dbHeader_Hash); //finish hash directly to DBHeader
				DBHeaderIO.WriteHash(bcs, s_dbHeader_Hash); //update hash in bcs

				sha256.Initialize();
				return new DB(buffer, dbHeader, aes, bcs, sha256);
				//note: buffer contains encrypted RNG, so no need to ZeroOut it.
			}
			catch
			{
				aes?.Dispose();
				bcs?.Dispose();
				sha256?.Dispose();
				throw;
			}
		}

		//public async Task AddIDataAsync(IData data)
		//{
		//	Memory<byte> m_buffer = _buffer;
		//	try
		//	{
		//		//prehash
		//		await ComputeHash().ConfigureAwait(false);
		//		using (SHA256 tmp_sha256 = _sha256.Clone())
		//		{
		//			Memory<byte> m_tmpHashBuffer = m_buffer.Slice(0, DBHeader.Layout.HashSize);
		//			tmp_sha256.Finalize(m_tmpHashBuffer.Span);
		//			if (!m_tmpHashBuffer.Span.SequenceEqual(_header.Hash.Span))
		//			{
		//				throw new DataBaseWrongHashException();
		//			}
		//		}

		//		//prepare data

		//		//IData data = DataCreator.InitIData(dataBox, m_buffer.Span); //create IData and write it to m_buffer
		//		int dataSize = data.CopyTo(m_buffer.Span);
		//		Memory<byte> m_data = m_buffer.Slice(0, dataSize);

		//		//finish hash
		//		_sha256.Transform(m_data.Span);
		//		_sha256.Finalize(_header.HashCore.Span);

		//		//write to bcs and update hash
		//		_bcs.WriteFast(m_data.Span);
		//		DBHeaderIO.UpdateHash(_bcs, _header); //update hash after adding

		//		_data.Add(data.Id, data); //finally add to dictionary
		//	}
		//	finally
		//	{
		//		_sha256.Initialize();
		//		MemoryHelper.ZeroOut(m_buffer.Span); //full size cauze buffer can contain decrypted bytes from Hash phase
		//	}
		//}

		/// <summary>
		/// Read BCS into SHA256, but dont finalize it.
		/// </summary>
		/// <returns></returns>
		//private async Task ComputeHash()
		//{
		//	Memory<byte> m_buffer = _buffer;
		//	await DBHeaderIO.ComputeDBHeaderHashAsync(_bcs, m_buffer, _sha256).ConfigureAwait(false);
		//	await DataIO.ComputeDatasHashAsync(_bcs, m_buffer, _sha256).ConfigureAwait(false);
		//}

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
