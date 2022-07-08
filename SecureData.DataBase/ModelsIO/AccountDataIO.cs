using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIO
{
	internal class AccountDataIO
	{
		public static void WriteToBuffer(AccountDataBox dataBox, Span<byte> s_buffer)
		{
			EncryptedDataIO.WriteToBuffer(dataBox, s_buffer);
			Span<byte> working;

			//Name
			working = s_buffer.Slice(AccountData.Layout.NameOffset, AccountData.Layout.NameSize);
			StringHelper.WriteWithRNG(working, dataBox.Name);

			//Description
			working = s_buffer.Slice(AccountData.Layout.DescriptionOffset, AccountData.Layout.DescriptionSize);
			StringHelper.WriteWithRNG(working, dataBox.Description);

			//Login
			working = s_buffer.Slice(AccountData.Layout.LoginOffset, AccountData.Layout.LoginSize);
			StringHelper.WriteWithRNG(working, dataBox.Login);

			//Password
			working = s_buffer.Slice(AccountData.Layout.PasswordOffset, AccountData.Layout.PasswordSize);
			StringHelper.WriteWithRNG(working, dataBox.Password);

			//RNG
			working = s_buffer.Slice(AccountData.Layout.RNGOffset, AccountData.Layout.RNGSize);
			Utils.RNG(working);
		}
	}
}
