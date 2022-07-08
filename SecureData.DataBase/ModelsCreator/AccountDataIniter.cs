using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.Cryptography.Hash;
using SecureData.DataBase.Models;
using SecureData.DataBase.ModelsIO;

namespace SecureData.DataBase.ModelsIniter
{
	internal static partial class DataCreator
	{
		public static AccountData Create(AccountDataBox dataBox, Span<byte> s_buffer)
		{
			byte[] hash, encryptedLogin, encryptedPassword, salt;
			dataBox.TimeStamp = DateTime.UtcNow;
			dataBox.Id = DB.GetId();
			if (!dataBox.IsEncrypted)
			{
				Utils.RNG(dataBox.Salt.Span);
			}
			AccountDataIO.WriteToBuffer(dataBox, s_buffer);
			using (SHA256 sha256 = new())
			{
				sha256.Transform(s_buffer.Slice(AccountData.Layout.HashingStart));
				sha256.Finalize(s_buffer.Slice(AccountData.Layout.HashOffset));
			}
			hash = s_buffer.Slice(AccountData.Layout.HashOffset, AccountData.Layout.HashSize).ToArray();
			encryptedLogin = s_buffer.Slice(AccountData.Layout.LoginOffset, AccountData.Layout.LoginSize).ToArray();
			encryptedPassword = s_buffer.Slice(AccountData.Layout.PasswordOffset, AccountData.Layout.PasswordSize).ToArray();
			salt = s_buffer.Slice(AccountData.Layout.SaltOffset, AccountData.Layout.SaltSize).ToArray();

			return new AccountData()
			return new AccountData(hash, dataBox.Id, dataBox.Parent!.Original, dataBox.TimeStamp,
				   dataBox.IsEncrypted, salt, dataBox.Name,
					encryptedLogin, encryptedPassword, dataBox.Description);
		}
	}
}
