using System.Reflection;

namespace SecureData.DataBase.Models.Abstract
{
	public abstract class LayoutBase
	{
		//TODO: check all dbsizes
		//static LayoutBase()
		//{
		//	int max = int.MinValue, current;
		//	foreach (var type in
		//		Assembly.GetExecutingAssembly()
		//		.GetTypes()
		//		.Where(x => !x.IsAbstract && x.IsClass && x.IsSubclassOf(typeof(LayoutBase))))
		//	{
		//		current = (int)type.GetField(nameof(DBSize))!.GetRawConstantValue()!;
		//		if (current % MultipleOf != 0)
		//			throw new ArithmeticException($"{nameof(DBSize)} ({current}) is not multiple of {MultipleOf}.");
		//		//dont count DBHeader
		//		if (type.DeclaringType!.Name != nameof(DBHeader) && current > max)
		//			max = current;
		//	}
		//	if (max <= 0)
		//		throw new ArithmeticException($"Finding {nameof(MaxDataSize)} results in {max}.");
		//	MaxDataSize = max;
		//}

		public static readonly int MaxDataSize = 1024; //TODO: find max data size!!!
	}
}
