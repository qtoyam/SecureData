using SecureData.DataBase.Models;

namespace SecureData.DataBase.ModelsIniter
{
	internal static partial class DataCreator
	{
		public static IData InitIData(IDataBox dataBox, Span<byte> buffer)
		{
			return dataBox switch
			{
				AccountDataBox box => Create(box, buffer),
				DataFolderBox box => Init(box, buffer),
				_ => throw new ArgumentException("Unknown type.", nameof(dataBox))
			};
		}
	}
}
