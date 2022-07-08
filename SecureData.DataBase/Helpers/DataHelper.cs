using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SecureData.DataBase.Models;

namespace SecureData.DataBase.Helpers
{
	internal static class DataHelper
	{
		//TODO: initer
		public static IData? InitIData(ReadOnlySpan<byte> data, DataType dataType)
		{
			return null;
		}

		//public const int MaxDataSize = 464;

		public static int GetSizeFromType(DataType dataType)
		{
			if (dataType.HasFlag(DataType.AccountData))
			{
				return AccountData.Size;
			}
			else if (dataType.HasFlag(DataType.DataFolder))
			{
				return DataFolder.Size;
			}
			else
			{
				throw new ArgumentException(null, nameof(dataType));
			}
		}

		public static void OrganizeFolders(IDictionary<uint, IData> data)
		{

		}
	}
}
