using System.Collections;

using SecureData.Storage.Models.Abstract;

namespace SecureData.Storage.Models;

public class FolderData : Data, IReadOnlyList<Data>
{
	private readonly List<Data> _childs = new();
	protected new const int SizeConst = Data.SizeConst;
	protected new const long DataTypeConst = 2U;
	protected new const int SensitiveOffsetConst = SizeConst;

	#region DB
	public override long DataType => DataTypeConst;
	#endregion
	protected FolderData(ReadOnlySpan<byte> raw) : base(raw) { }
	public FolderData() : base() { }

	public override int Size => SizeConst;
	public override int SensitiveOffset => SensitiveOffsetConst;


	public override void ClearSensitive() { }
	public override void LoadSensitive(ReadOnlySpan<byte> sensitiveBytes) { }
	protected override void FlushCore(Span<byte> raw) { }

	internal void Add(Data data)
	{
		_childs.Add(data);
	}

	public Data this[int index] => _childs[index];
	public int Count => _childs.Count;
	public IEnumerator<Data> GetEnumerator() => _childs.GetEnumerator();
	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
