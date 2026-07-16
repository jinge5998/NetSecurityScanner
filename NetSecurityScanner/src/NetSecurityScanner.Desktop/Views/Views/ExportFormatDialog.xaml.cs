using System.Windows;

namespace NetSecurityScanner.Views
{
    public partial class ExportFormatDialog : Window
    {
        public string SelectedFormat { get; private set; } = "CSV";

        public ExportFormatDialog()
        {
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (CsvRadio.IsChecked == true) SelectedFormat = "CSV";
            else if (JsonRadio.IsChecked == true) SelectedFormat = "JSON";
            else if (XmlRadio.IsChecked == true) SelectedFormat = "XML";
            DialogResult = true;
            Close();
        }
    }
}
