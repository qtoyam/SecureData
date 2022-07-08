using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.Hash;
using SecureData.Cryptography.Streams;
using SecureData.DataBase.Exceptions;
using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIO
{
	internal static class DataIO
	{
		public static async ValueTask<Dictionary<uint, IData>> ReadAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		{
			Dictionary<uint, IData> items = new();
			//assume data starts right after DBHeader
			bcs.Position = DBHeader.Layout.DBSize;
			int existingBytes = 0; //bytes read, hashed, but not transformed into IData yet
			int bytesRead;
			while (
				(bytesRead = await bcs.ReadAsync(m_buffer.Slice(existingBytes)).ConfigureAwait(false))
				> 0)
			{
				//TODO: parallel hash with semaphores
				//note: hash only read bytes except hashed already(existingBytes)
				sha256.Transform(m_buffer.Span.Slice(existingBytes, bytesRead - existingBytes));
				existingBytes = 0; //reset
				ReadOnlyMemory<byte> m_currentBuffer = m_buffer;
				while (m_currentBuffer.Length > 0)
				//note: current buffer length will be always >= 16 or == 0 (cauze of IData types size)
				//		so we can read atleast DataType (4 bytes)
				{
					DataType dt = (DataType)BitConverter.ToUInt32(m_buffer.Span);
					int size = DataHelper.GetSizeFromType(dt);
					if (m_currentBuffer.Length >= size) //current buffer has all data
					{
						IData? d = DataHelper.InitIData(m_currentBuffer.Span.Slice(0, size), dt);
						if (d != null) // == not deleted
						{
							items.Add(d.Id, d);
						}
						m_currentBuffer = m_currentBuffer.Slice(size); //slice current buffer (remove used data)
					}
					//TODO: split while(currentBuffer) into two:
					//1) loop while >= max data unit size
					//2) finish while > 0
					else //current buffer doesnt have enough data
					{
						//note: we can do this only when all IData types have size multiple of 16 (CTR block size).
						m_currentBuffer.CopyTo(m_buffer); //copy for future
						existingBytes = m_currentBuffer.Length; //dont read this region again
						break; //we need more bytes in current buffer
					}
				}
			}
			//situation: current IData not completed, but file ends
			if (existingBytes != 0)
			{
				throw DataBaseCorruptedException.WrongDBSize();
			}
			return items;
		}
	}
}
