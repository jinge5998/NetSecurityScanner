using System.Windows;
using NetSecurityScanner.Views;

namespace NetSecurityScanner
{
  public partial class MainWindow : Window
  {
    public MainWindow()
    {
      InitializeComponent();
      Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
      var generatorWindow = new LicenseCodeGeneratorWindow();
      generatorWindow.Show();
      Close();
    }
  }
}