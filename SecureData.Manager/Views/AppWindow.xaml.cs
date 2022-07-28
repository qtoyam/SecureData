﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

using SecureData.Manager.ViewModels;

namespace SecureData.Manager.Views
{
	/// <summary>
	/// Interaction logic for AppWindow.xaml
	/// </summary>
	public partial class AppWindow : Window
	{
		public AppWindow(AppWindowVM viewModel)
		{
			DataContext = viewModel;
			InitializeComponent();
			Style = (Style)Application.Current.Resources["CustomWindowChrome"];
		}
	}
}
