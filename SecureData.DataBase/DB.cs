using System.Collections.ObjectModel;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;
using SecureData.DataBase.ModelsIniter;
using SecureData.DataBase.ModelsIO;

using static SecureData.DataBase.Helpers.Utils;

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

		public static async Task<DB> InitAsync(string path, ReadOnlyMemory<byte> key)
		{
			//to be inited
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;
			SHA256? sha256 = null;

			DBHeader dbHeader;
			Dictionary<uint, IData> data;
			byte[] buffer = new byte[Consts.InitBufferSize];
			try
			{
				Memory<byte> m_buffer = buffer;
				sha256 = new SHA256();

				//read and hash dbheader
				using (var f = new FileStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.Read,
					Mode = FileMode.Open, //will throw if no file
					BufferSize = 0, //no buffering
					Options = FileOptions.SequentialScan
				}))
				{
					dbHeader = DBHeaderIO.Read(f, m_buffer.Span, sha256);
				}

				//create main BlockCryptoStream
				aes = new Aes256Ctr(key.Span, dbHeader.Salt.Span);
				bcs = new BlockCryptoStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.ReadWrite,
					BufferSize = 0, //no buffering
					Mode = FileMode.Open,
					Options = FileOptions.RandomAccess | FileOptions.Asynchronous
				}, aes, false);

				//hash RNG in dbheader
				await DBHeaderIO.ComputeRNGHashAsync(bcs, m_buffer, sha256).ConfigureAwait(false);

				//read and hash items
				data = await DataIO.ReadIDatasAsync(bcs, m_buffer, sha256).ConfigureAwait(false);
				Memory<byte> actualHash = m_buffer.Slice(0, SHA256.HashSize);
				sha256.Finalize(actualHash.Span);
				if (!dbHeader.Hash.Span.SequenceEqual(actualHash.Span))
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
				ZeroOut(buffer);
			}
		}

		public static async Task<DB> CreateAsync(string path, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> salt, string login)
		{
			//to be created
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;
			SHA256? sha256 = null;

			DBHeader dbHeader;
			Dictionary<uint, IData> data = new();
			byte[] buffer = new byte[Consts.InitBufferSize];
			try
			{
				Memory<byte> m_buffer = buffer;
				aes = new Aes256Ctr(key.Span, salt.Span);
				bcs = new BlockCryptoStream(path, new FileStreamOptions()
				{
					Share = FileShare.None,
					Access = FileAccess.Write,
					BufferSize = 0, //no buffering
					Mode = FileMode.CreateNew,
					Options = FileOptions.RandomAccess | FileOptions.Asynchronous
				}, aes, false);

				dbHeader = new DBHeader(new byte[DBHeader.Layout.HashSize], Consts.Version, salt, login);
				sha256 = new SHA256();
				//write and hash dbheader
				DBHeaderIO.WriteReal(bcs, dbHeader, m_buffer.Span, sha256);
				await DBHeaderIO.WriteRNGAsync(bcs, m_buffer, sha256).ConfigureAwait(false);
				sha256.Finalize(dbHeader.HashCore.Span);
				DBHeaderIO.UpdateHash(bcs, dbHeader); //update hash after rng

				sha256.Initialize();
				return new DB(buffer, dbHeader, aes, bcs, sha256, data);
				//note: buffer will be garbaged with encrypted stuff, so no need to ZeroOut it.
			}
			catch
			{
				aes?.Dispose();
				bcs?.Dispose();
				sha256?.Dispose();
				throw;
			}
		}

		public async Task AddIDataAsync(IDataBox dataBox)
		{
			Memory<byte> m_buffer = _buffer;
			try
			{
				await ComputeHash().ConfigureAwait(false);
				using (SHA256 tmp_sha256 = _sha256.Clone())
				{
					Memory<byte> m_tmpHashBuffer = m_buffer.Slice(0, DBHeader.Layout.HashSize);
					tmp_sha256.Finalize(m_tmpHashBuffer.Span);
					if (!m_tmpHashBuffer.Span.SequenceEqual(_header.Hash.Span))
					{
						throw new DataBaseWrongHashException();
					}
				}
				IData data = DataCreator.InitIData(dataBox, m_buffer.Span); //create IData and write it to m_buffer
				Memory<byte> m_data = m_buffer.Slice(0, data.DBSize);
				_sha256.Transform(m_data.Span);
				_sha256.Finalize(_header.HashCore.Span);
				_bcs.WriteFast(m_data.Span);
				DBHeaderIO.UpdateHash(_bcs, _header); //update hash after adding
				_data.Add(data.Id, data); //finally add to dictionary
			}
			finally
			{
				_sha256.Initialize();
				ZeroOut(m_buffer.Span);
			}
		}

		/// <summary>
		/// Read BCS into SHA256, but dont finalize it.
		/// </summary>
		/// <returns></returns>
		private async Task ComputeHash()
		{
			Memory<byte> m_buffer = _buffer;
			await DBHeaderIO.ComputeDBHeaderHashAsync(_bcs, m_buffer, _sha256).ConfigureAwait(false);
			await DataIO.ComputeDatasHashAsync(_bcs, m_buffer, _sha256).ConfigureAwait(false);
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
