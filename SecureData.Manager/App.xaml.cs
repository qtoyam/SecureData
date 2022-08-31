using System;
using System.Windows;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SecureData.Storage;
using SecureData.Manager.ViewModels;
using SecureData.Manager.Views;
using SecureData.Manager.Services;

namespace SecureData.Manager
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		[STAThread]
		static void Main()
		{
			using (IHost host = CreateHost())
			{
				host.Start();
				App app = new App()
				{
					ShutdownMode = ShutdownMode.OnLastWindowClose
				};
				app.InitializeComponent();
				var db = host.Services.GetRequiredService<DataBase>();
				if (!db.IsCreated)
				{
					CreateDBWindow createDBWindow = new CreateDBWindow();
					createDBWindow.ShowDialog();
					var argonOptions = createDBWindow.VM.ArgonOptions;
					if (argonOptions is null)
					{
						return;
					}
					db.Create("default", createDBWindow.VM.Password, argonOptions);
				}
				app.MainWindow = host.Services.GetRequiredService<AppWindow>();
				app.MainWindow.Visibility = Visibility.Visible;
				app.Run();
			}
		}

		static IHost CreateHost() =>
			new HostBuilder()
			.ConfigureHostOptions((options) =>
			{
				options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
				options.ShutdownTimeout = TimeSpan.FromSeconds(10);
			})
			.UseDefaultServiceProvider((options) =>
			{
#if DEBUG
				//validate all on debug
				options.ValidateOnBuild = true;
				options.ValidateScopes = true;
#endif
			})
			.UseEnvironment("Development")
			.ConfigureAppConfiguration((context, configurationBuilder) =>
			{
				configurationBuilder.Sources.Clear();
			})
			.ConfigureLogging((loggingBuilder) =>
			{
#if DEBUG
				//loggers on debug
				loggingBuilder.AddDebug();
				loggingBuilder.SetMinimumLevel(LogLevel.Debug);
#else
				//loggers on release
#endif
			})
			.ConfigureServices((context, services) =>
			{
				//services, hosted services, configs
				services.AddSingleton<DataBase>((_) => new DataBase(Paths.Database));
				services.AddSingleton<Notifier>((_) =>
				{
					//TODO: owner
					return new Notifier(msg => MessageBox.Show(Current.MainWindow, msg), Current.Shutdown);
				});
				services.AddSingleton<ParallelRunner>();

				services.AddSingleton<AppWindow>();
				services.AddSingleton<AppWindowVM>();

				services.AddSingleton<AuthVM>();
				services.AddSingleton<PasswordsVM>();
			})
			.Build();
	}
}
