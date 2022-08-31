using System;
using System.Diagnostics;
using System.Threading.Tasks;

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using SecureData.Cryptography.Hash;
using SecureData.Manager.Services;

namespace SecureData.Manager.ViewModels;

[ObservableObject]
public partial class CreateDBVM
{
	private readonly Notifier _notifier;
	public CreateDBVM(Notifier notifier)
	{
		_notifier = notifier;
	}

	private readonly Stopwatch _stopwatch = new();
	private readonly byte[] _salt = new byte[16];
	private readonly byte[] _hash = new byte[32];
	[ObservableProperty]
	[NotifyCanExecuteChangedFor(nameof(CreateCommand))]
	private string _password = string.Empty;

	[ObservableProperty]
	[NotifyCanExecuteChangedFor(nameof(CreateCommand))]
	private uint? _time = null;

	[ObservableProperty]
	[NotifyCanExecuteChangedFor(nameof(CreateCommand))]
	private uint? _memory = null;

	[ObservableProperty]
	[NotifyCanExecuteChangedFor(nameof(CreateCommand))]
	private uint? _threads = null;

	public Argon2dOptions? ArgonOptions { get; private set; }

	private bool CanCreate() => Time.HasValue && Memory.HasValue && Threads.HasValue
		&& Time > 0 && Memory.Value > 0 && Threads.Value > 0 && !string.IsNullOrEmpty(Password);

	[RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanCreate))]
	private async Task CreateAsync()
	{
		TimeSpan maxTime = TimeSpan.FromSeconds(Time!.Value);
		Argon2dOptions argonOptions = new(10, Memory!.Value, Threads!.Value);
		await ParallelRunner.Run(() =>
		{

			uint incr = 2;
			while (true)
			{
				_stopwatch.Restart();
				Argon2d.ComputeHash(argonOptions, Password, _salt, _hash);
				_stopwatch.Stop();
				if (_stopwatch.Elapsed.Seconds <= maxTime.Seconds / 2)
				{
					argonOptions.TimeCost += incr;
					incr *= 2;
				}
				else if (_stopwatch.Elapsed < maxTime)
				{
					argonOptions.TimeCost++;
				}
				else
				{
					break;
				}
			}
			argonOptions.TimeCost--;
		}, _notifier).ConfigureAwait(false);
		ArgonOptions = argonOptions;
		_notifier.Notify("Database created.");
		_notifier.Exit();
	}
}
