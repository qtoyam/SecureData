using System.Windows;

using SecureData.Manager.ViewModels;

namespace SecureData.Manager.Views;

public partial class CreateDBWindow : Window
{
	public CreateDBWindow()
	{
		Style = (Style)Application.Current.Resources["CustomWindowChrome"];
		DataContext = new CreateDBVM(new Services.Notifier(Notify, Close));
		InitializeComponent();
	}

	public CreateDBVM VM => (CreateDBVM)DataContext;

	public void Notify(string message) => MessageBox.Show(this, message);
}
