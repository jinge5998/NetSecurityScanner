using System.Windows;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views.Views
{
    public partial class ReportFormatDialog : Window
    {
        public ReportOptions Options { get; private set; } = new ReportOptions();

        public ReportFormatDialog()
        {
            InitializeComponent();
        }

        public ReportFormatDialog(ScanHistory history) : this()
        {
            SubTitleText.Text = $"为扫描记录 {history.ScanId} ({history.Target}) 生成专业报告";
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            var format = HistoryReportFormat.PDF;
            if (PdfRadio.IsChecked == true) format = HistoryReportFormat.PDF;
            else if (WordRadio.IsChecked == true) format = HistoryReportFormat.Word;
            else if (HtmlRadio.IsChecked == true) format = HistoryReportFormat.HTML;

            Options = new ReportOptions
            {
                Format = format,
                IncludeExecutiveSummary = ExecutiveSummaryCheck.IsChecked == true,
                IncludeVulnerabilityList = VulnerabilityListCheck.IsChecked == true,
                IncludeRemediation = RemediationCheck.IsChecked == true,
                IncludeStatistics = StatisticsCheck.IsChecked == true,
                IncludeCharts = ChartsCheck.IsChecked == true,
                IncludeAppendix = AppendixCheck.IsChecked == true,
                CompanyName = CompanyNameTextBox.Text,
                ReportType = ReportTypeTextBox.Text,
                ConfidentialLevel = (ConfidentialCombo.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "机密",
                AuthorName = AuthorNameTextBox.Text
            };

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
