using System;
using System.Windows;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using SecureData.DataBase;
using SecureData.Manager.ViewModels;
using SecureData.Manager.Views;

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
				LoginWindow loginWindow = new();
				loginWindow.ShowDialog();
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
				services.AddSingleton<AppWindow>();
				services.AddSingleton<AppWindowVM>();
			})
			.Build();
	}
}
