using SecureData.DataBase.Helpers;
using SecureData.DataBase.Models.Abstract;
using SecureData.DataBase.Services;

namespace SecureData.DataBase.Models
{
	public class FolderData : Data
	{
		private readonly Dictionary<uint, Data> _childs = new();
		public IReadOnlyDictionary<uint, Data> Childs => _childs;
		private static class Layout
		{
			public const int NameOffset = Data.SizeConst;
			public const int NameSize = 64;

			public const int DescriptionOffset = NameOffset + NameSize;
			public const int DescriptionSize = 256;

			public const int RNGOffset = DescriptionOffset + DescriptionSize;
			public const int RNGSize = 64;
		}
		protected new const int SizeConst = Layout.RNGOffset + Layout.RNGSize;
		protected new const uint DataTypeConst = 2U;

		#region DB
		#region Private write-access
		private string _name = string.Empty;
		private string _description = string.Empty;
		#endregion
		public override uint DataType => DataTypeConst;

		public string Name
		{
			get
			{
				EnsureParentUnlocked();
				return _name;
			}
			set
			{
				Set(ref _name, value);
			}
		}
		public string Description
		{
			get
			{
				EnsureParentUnlocked();
				return _description;
			}
			set
			{
				Set(ref _description, value);
			}
		}
		#endregion
		protected FolderData(Memory<byte> raw) : base(raw, false) { }
		public FolderData() : base(new byte[SizeConst], true) { }

		public override int Size => SizeConst;
		protected override int ObjectCipherStart => Layout.RNGOffset;

		internal void AddOnInit(Data data)
		{
			_childs.Add(data.Id, data);
		}

		protected override void UpdateData(ReadOnlySpan<byte> raw)
		{
			base.UpdateData(raw);
			_name = BinaryHelper.ReadString(raw.Slice(Layout.NameOffset, Layout.NameSize));
			_description = BinaryHelper.ReadString(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize));
		}

		protected override void FlushAll(Span<byte> raw)
		{
			base.FlushAll(raw);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.NameOffset, Layout.NameSize), _name);
			BinaryHelper.WriteWRNG(raw.Slice(Layout.DescriptionOffset, Layout.DescriptionSize), _description);
		}

		protected override void LockExternal(Cipher cipher)
		{
			base.LockExternal(cipher);
			LockChilds(cipher);
		}
		protected override void UnlockExternal(Cipher cipher)
		{
			base.UnlockExternal(cipher);
			UnlockChilds(cipher);
		}

		protected override void ClearData()
		{
			base.ClearData();
			_name = string.Empty;
			_description = string.Empty;
		}

		protected override void LockLayerExternal(Cipher cipher)
		{
			base.LockLayerExternal(cipher);
			LockChilds(cipher);
		}

		protected override void UnlockLayerExternal(Cipher cipher)
		{
			base.UnlockLayerExternal(cipher);
			UnlockChilds(cipher);
		}

		protected override void MakeEncryptedExternal(Cipher cipher)
		{
			base.MakeEncryptedExternal(cipher);
			foreach(var child in Childs.Values)
			{
				child.ChangeParentLayers(1);
			}
		}
		protected override void MakeUnencryptedExternal(Cipher cipher)
		{
			base.MakeUnencryptedExternal(cipher);
			foreach(var child in Childs.Values)
			{
				child.ChangeParentLayers(-1);
			}
		}

		public void AddChild(Data data)
		{
			EnsureVisible();
			data.Parent = this;
			data.ChangeParentLayers(ParentLockedLayers + (IsEncrypted ? 1 : 0));
		}

		private void LockChilds(Cipher cipher)
		{
			foreach (Data child in Childs.Values)
			{
				child.LockLayer(cipher);
			}
		}
		private void UnlockChilds(Cipher cipher)
		{
			foreach (Data child in Childs.Values)
			{
				child.UnlockLayer(cipher);
			}
		}
	}
}
