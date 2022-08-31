using System;
using System.Threading.Tasks;

namespace SecureData.Manager.Services;

public class ParallelRunner
{
	private readonly Notifier _notifier;

	public ParallelRunner(Notifier notifier)
	{
		_notifier = notifier;
	}

	public Task Run(Action action, bool configureAwait = false)
	{
		return Run(action, _notifier, configureAwait);
	}

	public static async Task Run(Action action, Notifier notifier, bool configureAwait = false)
	{
		try
		{
			await Task.Run(action).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			notifier.NotifyException(ex);
		}
	}
}
