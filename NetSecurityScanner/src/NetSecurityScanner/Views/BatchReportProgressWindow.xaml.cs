using System.Windows;

namespace NetSecurityScanner.Views.Views
{
    public partial class BatchReportProgressWindow : Window
    {
        private int _total;

        public BatchReportProgressWindow()
        {
            InitializeComponent();
        }

        public BatchReportProgressWindow(int total) : this()
        {
            _total = total;
            CounterText.Text = $"0 / {total}";
            ProgressBar.Maximum = total;
        }

        public void UpdateProgress(int current, string status)
        {
            ProgressBar.Value = current;
            CounterText.Text = $"{current} / {_total}";
            StatusText.Text = status;
        }
    }
}
