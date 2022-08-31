using System.Windows;

using SecureData.Manager.ViewModels;

namespace SecureData.Manager.Views;

public partial class AppWindow
{
	public AppWindow(AppWindowVM viewModel)
	{
		DataContext = viewModel;
		InitializeComponent();
		Style = (Style)Application.Current.Resources["CustomWindowChrome"];
	}
}
