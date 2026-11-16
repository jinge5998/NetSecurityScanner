using System.ComponentModel;

namespace NetSecurityScanner.Models
{
    public class PortScanResult : INotifyPropertyChanged
    {
        private bool _isSelected;
        private bool _isImportant; // 新增：用于重点关注标记（P0右键菜单功能）
        
        public string TargetIp { get; set; } = string.Empty;
        public int PortNumber { get; set; }
        public string Status { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string ServiceVersion { get; set; } = string.Empty;
        public string ResponseTime { get; set; } = "-";

        /// <summary>
        /// 扫描结果的可信度：
        /// "高" - TCP SYN/ACK 收到完整 banner / 三次握手成功
        /// "中" - 端口响应但 banner 获取失败
        /// "低" - 仅超时判定为"开放或过滤"或经过重试仍模糊
        /// </summary>
        public string Confidence { get; set; } = "中";

        /// <summary>
        /// 扫描耗时（毫秒）—— 用于精度分析与排序
        /// </summary>
        public long ScanDurationMs { get; set; } = 0;

        /// <summary>
        /// 风险等级（中文：严重/高危/中危/低危/信息）
        /// 用于在 UI 中按风险排序与着色
        /// </summary>
        public string RiskLevel { get; set; } = "";

        /// <summary>
        /// 风险评分（数值）：Critical=30, High=15, Medium=8, Low=3, Info=1
        /// 用于风险计算与排序
        /// </summary>
        public int RiskScore { get; set; } = 0;

        /// <summary>
        /// 服务类别（中文：Web 服务/数据库/远程访问 等）
        /// </summary>
        public string ServiceCategory { get; set; } = "";

        /// <summary>
        /// 漏洞提示（基于端口的常见漏洞/CVE 提示）
        /// </summary>
        public string VulnHint { get; set; } = "";

        /// <summary>
        /// 风险描述（如：Telnet 明文协议、Docker API 未授权 等）
        /// </summary>
        public string RiskDescription { get; set; } = "";
        
        public bool IsSelected
        {
            get { return _isSelected; }
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        /// <summary>
        /// 是否被标记为重点关注（P0增强功能）
        /// </summary>
        public bool IsImportant
        {
            get { return _isImportant; }
            set
            {
                _isImportant = value;
                OnPropertyChanged(nameof(IsImportant));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}