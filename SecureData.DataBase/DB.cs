using System.Collections.ObjectModel;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.Cryptography.SymmetricEncryption;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;
using SecureData.DataBase.ModelsIO;

namespace SecureData.DataBase
{
	public sealed class DB : IDisposable, IAsyncDisposable
	{
		private static class Consts
		{
			public const uint Version = 1;
			//should be greater than DBHeader real size and max IData size
			public const int InitBufferSize = 128 * 1024;
		}

		private readonly Aes256Ctr _aes; //not autodisposable
#if DEBUG//for tests
		public
#else
		private 
#endif
		readonly DBHeader _header;
		private readonly BlockCryptoStream _bcs;
		private readonly Dictionary<uint, IData> _data;
		private readonly byte[] _buffer;

		private readonly ReadOnlyDictionary<uint, IData> _items;
		public ReadOnlyDictionary<uint, IData> Items => _items;

		private DB(Aes256Ctr aes, DBHeader dbHeader, BlockCryptoStream bcs, Dictionary<uint, IData> data, byte[] buffer)
		{
			_aes = aes;
			_header = dbHeader;
			_bcs = bcs;
			_data = data;
			_items = new(_data);
			_buffer = buffer;
		}

		public static async Task<DB> InitAsync(string path, ReadOnlyMemory<byte> key)
		{
			//to be inited
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;

			DBHeader dbHeader;
			Dictionary<uint, IData> data;

			//disposable resources
			SHA256? sha256 = null;
			try
			{
				sha256 = new SHA256();

				byte[] buffer = new byte[Consts.InitBufferSize];

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
					dbHeader = DBHeaderIO.Read(f, buffer, sha256);
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
				await DBHeaderIO.ReadRNGAsync(bcs, buffer, sha256).ConfigureAwait(false);

				//read and hash items
				data = await DataIO.ReadIDatasAsync(bcs, buffer, sha256).ConfigureAwait(false);
				byte[] actualHash = sha256.Finalize();
				if (!dbHeader.Hash.Span.SequenceEqual(actualHash))
				{
					throw new DataBaseWrongHashException();
				}
				//TODO: parallel organize data
				DataHelper.OrganizeFolders(data);

				return new DB(aes, dbHeader, bcs, data, buffer);
			}
			catch
			{
				bcs?.Dispose();
				aes?.Dispose();
				throw;
			}
			finally
			{
				sha256?.Dispose();
			}
		}

		public static async Task<DB> CreateAsync(string path, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> salt, string login)
		{
			//to be created
			//disposable on exception
			Aes256Ctr? aes = null;
			BlockCryptoStream? bcs = null;
			DBHeader dbHeader;
			Dictionary<uint, IData> data = new();

			byte[] buffer = new byte[Consts.InitBufferSize];
			Memory<byte> m_buffer = buffer;
			try
			{
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
				using (SHA256 sha256 = new())
				{
					//write and hash dbheader
					DBHeaderIO.WriteReal(bcs, dbHeader, m_buffer.Span, sha256);
					await DBHeaderIO.WriteRNGAsync(bcs, m_buffer, sha256).ConfigureAwait(false);
					sha256.Finalize(dbHeader.HashCore.Span);
				}
				DBHeaderIO.WriteHash(bcs, dbHeader); //update hash after rng

				return new DB(aes, dbHeader, bcs, data, buffer);
			}
			catch
			{
				aes?.Dispose();
				bcs?.Dispose();
				throw;
			}
		}

		public async Task AddIDataAsync(IData data)
		{

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
