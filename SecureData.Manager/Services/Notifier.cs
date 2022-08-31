using System;

namespace SecureData.Manager.Services;

public class Notifier
{
	private readonly Action<string> _notify;
	private readonly Action<string> _notifyWarning;
	private readonly Action<string> _notifyError;
	private readonly Action<Exception> _notifyException;
	private readonly Action _exit;

	public Notifier(Action<string> notifyAny, Action exit)
	{
		_notify = _notifyWarning = _notifyError = notifyAny;
		_notifyException = e => _notifyError(e.Message);
		_exit = exit;
	}

	public Notifier(Action<string> notify, Action<string> notifyWarning, Action<string> notifyError, Action<Exception> notifyException, Action exit)
	{
		_notify = notify;
		_notifyWarning = notifyWarning;
		_notifyError = notifyError;
		_notifyException = notifyException;
		_exit = exit;
	}

	public void Notify(string message) => _notify(message);
	public void NotifyWarning(string warning) => _notifyWarning(warning);
	public void NotifyError(string error) => _notifyError(error);
	public void NotifyException(Exception exception) => _notifyException(exception);

	public void Exit() => _exit();
}
