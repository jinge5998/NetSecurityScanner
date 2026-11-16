using System.Windows;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views.Views
{
    public partial class ReportProgressWindow : Window
    {
        public ReportProgressWindow()
        {
            InitializeComponent();
        }

        public ReportProgressWindow(ScanHistory history, HistoryReportFormat format) : this()
        {
            var formatName = format switch
            {
                HistoryReportFormat.PDF => "PDF",
                HistoryReportFormat.Word => "Word",
                HistoryReportFormat.HTML => "HTML",
                _ => ""
            };
            TitleText.Text = $"📑 正在生成 {formatName} 报告: {history.Target}";
        }

        public void UpdateProgress(double value, string status)
        {
            ProgressBar.Value = value;
            StatusText.Text = status;
        }
    }
}
