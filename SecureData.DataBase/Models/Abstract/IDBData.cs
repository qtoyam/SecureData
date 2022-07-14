using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureData.DataBase.Models.Abstract
{
	internal interface IDBData
	{
		int Changes { get; }
		void Update();
		void Flush();
	}
}
