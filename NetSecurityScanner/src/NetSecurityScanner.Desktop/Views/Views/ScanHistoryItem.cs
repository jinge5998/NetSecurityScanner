using NetSecurityScanner.Models;
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSecurityScanner.Views
{
    /// <summary>
    /// 布尔值到勾选符号的转换器
    /// </summary>
    public class BoolToCheckConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value is bool b && b) ? "☑" : "☐";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// 布尔值到背景色的转换器（选中=橙色，未选中=白色）
    /// </summary>
    public class BoolToBgConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value is bool b && b) ? new SolidColorBrush(Color.FromRgb(255, 193, 7))  // 橙色 #FFC107
                                         : new SolidColorBrush(Colors.White);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// 布尔值到前景色的转换器（选中=白色，未选中=深灰）
    /// </summary>
    public class BoolToFgConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return (value is bool b && b) ? new SolidColorBrush(Colors.White)
                                         : new SolidColorBrush(Color.FromRgb(80, 80, 80));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// 可勾选选择的扫描历史记录包装类，用于 DataGrid 展示
    /// </summary>
    public class SelectableScanHistory : INotifyPropertyChanged
    {
        private int _rowNumber;
        public int RowNumber
        {
            get => _rowNumber;
            set { _rowNumber = value; OnPropertyChanged(); }
        }

        public ScanHistory History { get; set; }

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected != value)
                {
                    _isSelected = value;
                    OnPropertyChanged();
                }
            }
        }

        public SelectableScanHistory(ScanHistory history)
        {
            History = history;
        }

        // 代理属性方便 XAML 绑定
        public string ScanId => History.ScanId;
        public string Target => History.Target;
        public DateTime ScanTime => History.ScanTime;
        public string ScanMode => History.ScanMode;
        public int TotalVulnerabilities => History.TotalVulnerabilities;
        public int CriticalCount => History.CriticalCount;
        public int HighCount => History.HighCount;
        public int MediumCount => History.MediumCount;
        public int LowCount => History.LowCount;
        public TimeSpan Duration => History.Duration;
        public string ScanStatus => History.ScanStatus;

        private bool _isDuplicateTarget;
        /// <summary>
        /// 是否为重复目标（在当前扫描记录中已存在相同 Target）
        /// </summary>
        public bool IsDuplicateTarget
        {
            get => _isDuplicateTarget;
            set
            {
                if (_isDuplicateTarget != value)
                {
                    _isDuplicateTarget = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(TargetDisplay));
                }
            }
        }

        private int _duplicateCount;
        /// <summary>
        /// 重复扫描次数
        /// </summary>
        public int DuplicateCount
        {
            get => _duplicateCount;
            set
            {
                if (_duplicateCount != value)
                {
                    _duplicateCount = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(TargetDisplay));
                }
            }
        }

        /// <summary>
        /// 用于在"目标"列上显示带重复标记的文本
        /// </summary>
        public string TargetDisplay => _isDuplicateTarget
            ? $"{Target}  (×{_duplicateCount})"
            : Target;

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
