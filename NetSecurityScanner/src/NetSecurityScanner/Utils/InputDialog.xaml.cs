using System;
using System.Windows;

namespace NetSecurityScanner.Utils
{
    public partial class InputDialog : Window
    {
        public string Answer { get; private set; }

        public InputDialog()
        {
            InitializeComponent();
        }

        public InputDialog(string title, string prompt) : this()
        {
            Title = title;
            PromptTextBlock.Text = prompt;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            Answer = InputTextBox.Text;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            Answer = null;
            DialogResult = false;
            Close();
        }
    }
}