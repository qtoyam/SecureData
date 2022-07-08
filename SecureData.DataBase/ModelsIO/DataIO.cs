using System;
using System.Collections.Generic;
using System.Data;
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
		//TODO: reader
		/// <summary>
		/// Reads IData from <paramref name="s_buffer"/>.
		/// </summary>
		/// <param name="s_buffer">Must be atleast <see cref="LayoutBase.MaxDataSize"/> size.</param>
		/// <returns><see langword="null"/> if <see cref="IData"/> marked as <see cref="DataType.Deleted"/>, otherwise inited <see cref="IData"/>.</returns>
		private static IData? ReadIData(ReadOnlySpan<byte> s_buffer, out int bytesRead)
		{
			bytesRead = 0;
			return null;
		}

		public static void WriteToBuffer(IDataBox dataBox, Span<byte> s_buffer)
		{
			Span<byte> working;

			//DataType
			working = s_buffer.Slice(IData.Layout.DataTypeOffset);
			BinaryHelper.Write(working, (uint)dataBox.DataType);

			//Id
			working = s_buffer.Slice(IData.Layout.IdOffset);
			BinaryHelper.Write(working, dataBox.Id);

			//Parent
			working = s_buffer.Slice(IData.Layout.ParentIdOffset);
			BinaryHelper.Write(working, dataBox.Parent?.Id ?? 0U);

			//TimeStamp
			working = s_buffer.Slice(IData.Layout.TimeStampOffset);
			BinaryHelper.Write(working, dataBox.TimeStamp.ToBinary());
		}

		public static async Task<Dictionary<uint, IData>> ReadIDatasAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		{
			Dictionary<uint, IData> items = new();
			//assume data starts right after DBHeader
			bcs.Position = DBHeader.Layout.DBSize;
			int existingBytes = 0; //bytes read & hashed but not transformed into IData yet
			int bytesRead;
			while (
				//read full buffer except existingBytes
				(bytesRead = await bcs.ReadAsync(m_buffer.Slice(existingBytes)).ConfigureAwait(false))
				> 0)
			{
				//TODO: parallel hash with semaphores
				//note: hash only read bytes except hashed already(existingBytes)
				sha256.Transform(m_buffer.Span.Slice(existingBytes, bytesRead - existingBytes));
				int readTo;
				if (bytesRead == (m_buffer.Length - existingBytes)) //current buffer filled, so assume there is extra bytes in BCS
				{
					readTo = LayoutBase.MaxDataSize; //read while we sure that current buffer is enough to complete any DataType
				}
				else //end of file, last buffer
				{
					readTo = 0; //read all buffer
				}
				ReadOnlyMemory<byte> m_currentBuffer = m_buffer;

				while (m_currentBuffer.Length >= readTo)
				{
					IData? data = ReadIData(m_currentBuffer.Span, out int br);
					if (data != null) //not deleted
					{
						items.Add(data.Id, data);
					}
					m_currentBuffer = m_currentBuffer.Slice(br);
				}
				if (m_currentBuffer.Length != 0)
				{
					// will throw in ReadIData if not readTo == 0
					m_currentBuffer.CopyTo(m_buffer); //copy for next iteration
					existingBytes = m_currentBuffer.Length; //dont read/hash this region again
				}
				else
				{
					existingBytes = 0; //reset cauze processed all data
				}
			}
			return items;
		}

		public static async Task ComputeDatasHashAsync(BlockCryptoStream bcs, Memory<byte> m_buffer, SHA256 sha256)
		{
			bcs.Position = DBHeader.Layout.DBSize;
			int bytesRead;
			while ((bytesRead = await bcs.ReadAsync(m_buffer).ConfigureAwait(false)) > 0)
			{
				sha256.Transform(m_buffer.Span.Slice(0, bytesRead));
			}
		}
	}
}
