using System.Diagnostics.CodeAnalysis;

using Microsoft.Win32;

using SecureData.Cryptography.Hash;
using SecureData.Manager.Views;
using SecureData.Storage;

namespace SecureData.Manager.Services;

public record GetPathOptions(string Action);

public class UserInteractionService
{
	private SaveFileDialog? _saveFileDialog;
	private OpenFileDialog? _openFileDialog;

	private SaveFileDialog GetSaveFileDialog(GetPathOptions getPathOptions)
	{
		if (_saveFileDialog is null)
		{
			_saveFileDialog = new();
		}
		else
		{
			_saveFileDialog.Reset();
		}

		_saveFileDialog.Title = getPathOptions.Action;

		return _saveFileDialog;
	}
	private OpenFileDialog GetOpenFileDialog(GetPathOptions getPathOptions)
	{
		if (_openFileDialog is null)
		{
			_openFileDialog = new();
		}
		else
		{
			_openFileDialog.Reset();
		}

		_openFileDialog.Title = getPathOptions.Action;

		return _openFileDialog;
	}

	public bool TryGetSavePath([NotNullWhen(true)] out string? path, GetPathOptions getPathOptions)
	{
		return TryGetFilePathFromDialog(out path, GetSaveFileDialog(getPathOptions));
	}

	public bool TryGetOpenPath([NotNullWhen(true)] out string? path, GetPathOptions getPathOptions)
	{
		return TryGetFilePathFromDialog(out path, GetOpenFileDialog(getPathOptions));
	}

	public bool TryCreateDataBase([NotNullWhen(true)] out DataBase? dataBase)
	{
		if (TryGetSavePath(out var dbPath, new GetPathOptions("Create database")))
		{
			var createDBWindow = new CreateDBWindow();
			createDBWindow.ShowDialog();
			if (createDBWindow.VM.ArgonOptions is Argon2dOptions argon2DOptions)
			{
				dataBase = new DataBase(dbPath);
				dataBase.Create("login", createDBWindow.VM.Password, argon2DOptions);
				return true;
			}
		}
		dataBase = null;
		return false;
	}

	private static bool TryGetFilePathFromDialog([NotNullWhen(true)] out string? path, FileDialog fileDialog)
	{
		if (fileDialog.ShowDialog() is true)
		{
			path = fileDialog.FileName;
			return true;
		}
		path = null;
		return false;
	}
}
