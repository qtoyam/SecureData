using SecureData.DataBase.Models.Abstract;

namespace SecureData.DataBase.Models;

public class FolderData : Data
{
	private readonly Dictionary<uint, Data> _childs = new();
	public IReadOnlyDictionary<uint, Data> Childs => _childs;
	protected new const int SizeConst = Data.SizeConst;
	protected new const long DataTypeConst = 2U;

	#region DB
	public override long DataType => DataTypeConst;
	#endregion
	protected FolderData(ReadOnlySpan<byte> raw) : base(raw) { }
	public FolderData() : base() { }

	public override int Size => SizeConst;
	public override int SensitiveOffset => Size;

	internal void Add(Data data)
	{
		_childs.Add(data.Id, data);
	}

	public override void ClearSensitive() { }
	public override void LoadSensitive(ReadOnlySpan<byte> raw) { }
	protected override void FlushCore(Span<byte> raw) { }
}
