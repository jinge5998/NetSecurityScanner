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