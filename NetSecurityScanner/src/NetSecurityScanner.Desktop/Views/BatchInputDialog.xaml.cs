using System.Windows;

namespace NetSecurityScanner.Views
{
    public partial class BatchInputDialog : Window
    {
        public string InputText => InputTextBox.Text;
        public string WindowTitle { get; set; } = "输入";

        public BatchInputDialog()
        {
            InitializeComponent();
        }

        public BatchInputDialog(string title, string message) : this()
        {
            Title = title;
            WindowTitle = title;
            MessageText.Text = message;
            Loaded += (s, e) => InputTextBox.Focus();
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
