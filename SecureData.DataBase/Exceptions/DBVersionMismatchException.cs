﻿namespace SecureData.DataBase.Exceptions
{
	public class DBVersionMismatchException : Exception
	{
		public DBVersionMismatchException(uint dbVersion, uint programVersion) 
			: base($"Version mismatch. DB: {dbVersion}, program: {programVersion}")
		{

		}
	}
}
