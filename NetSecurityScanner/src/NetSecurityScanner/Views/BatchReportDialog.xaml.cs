using System.Windows;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Views.Views
{
    public partial class BatchReportDialog : Window
    {
        public HistoryReportFormat Format { get; private set; } = HistoryReportFormat.PDF;
        public bool IncludeExecutiveSummary => SummaryCheck.IsChecked == true;
        public bool IncludeVulnerabilityList => VulnCheck.IsChecked == true;
        public bool IncludeRemediation => RemediationCheck.IsChecked == true;
        public bool IncludeStatistics => StatsCheck.IsChecked == true;
        public bool IncludeCharts => true;
        public string CompanyName => CompanyTextBox.Text;

        public BatchReportDialog()
        {
            InitializeComponent();
        }

        public BatchReportDialog(int count) : this()
        {
            CountText.Text = $"将为 {count} 条扫描记录生成报告";
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            Format = (FormatCombo.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() switch
            {
                "PDF 报告" => HistoryReportFormat.PDF,
                "Word 文档" => HistoryReportFormat.Word,
                "HTML 网页" => HistoryReportFormat.HTML,
                _ => HistoryReportFormat.PDF
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
