using System.ComponentModel;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 摄像头批量扫描列表项（INotifyPropertyChanged，供列表绑定实时刷新）。
    /// </summary>
    public class CameraBatchScanItem : INotifyPropertyChanged
    {
        private string _status = "等待中";
        private string _vendor = "";
        private int _openPortsCount;
        private int _findingsCount;
        private int _criticalCount;
        private int _highCount;
        private string _riskScore = "—";
        private string _durationText = "";
        private string _errorMessage = "";

        public string IpAddress { get; set; } = "";
        public string Status { get => _status; set { _status = value; OnPropertyChanged(nameof(Status)); } }
        public string Vendor { get => _vendor; set { _vendor = value; OnPropertyChanged(nameof(Vendor)); } }
        public int OpenPortsCount { get => _openPortsCount; set { _openPortsCount = value; OnPropertyChanged(nameof(OpenPortsCount)); } }
        public int FindingsCount { get => _findingsCount; set { _findingsCount = value; OnPropertyChanged(nameof(FindingsCount)); } }
        public int CriticalCount { get => _criticalCount; set { _criticalCount = value; OnPropertyChanged(nameof(CriticalCount)); } }
        public int HighCount { get => _highCount; set { _highCount = value; OnPropertyChanged(nameof(HighCount)); } }
        public string RiskScore { get => _riskScore; set { _riskScore = value; OnPropertyChanged(nameof(RiskScore)); } }
        public string DurationText { get => _durationText; set { _durationText = value; OnPropertyChanged(nameof(DurationText)); } }
        public string ErrorMessage { get => _errorMessage; set { _errorMessage = value; OnPropertyChanged(nameof(ErrorMessage)); } }

        /// <summary>扫描完成后保留完整结果，供双击查看详情与导出汇总报告。</summary>
        public CameraScanResult? Result { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
