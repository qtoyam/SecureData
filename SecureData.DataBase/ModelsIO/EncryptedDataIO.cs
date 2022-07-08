using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIO
{
	internal class EncryptedDataIO
	{
		public static void WriteToBuffer(IEncryptedDataBox dataBox, Span<byte> s_buffer)
		{
			DataIO.WriteToBuffer(dataBox, s_buffer);
			Span<byte> working;

			//IsEncrypted
			working = s_buffer.Slice(IEncryptedData.Layout.IsEncryptedOffset);
			BinaryHelper.Write(working, dataBox.IsEncrypted);

			//Salt
			working = s_buffer.Slice(IEncryptedData.Layout.SaltOffset);
			BinaryHelper.Write(working, dataBox.Salt.Span);
		}
	}
}
