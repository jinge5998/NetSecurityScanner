using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace NetSecurityScanner.Utils
{
    // 风险等级到颜色的转换器
    public class RiskLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string riskLevel = value as string;
            if (string.IsNullOrEmpty(riskLevel))
                return Brushes.Black;
            
            switch (riskLevel.ToLower())
            {
                case "高":
                case "高风险":
                case "危险":
                    return Brushes.Red;
                case "中":
                case "中风险":
                case "警告":
                    return Brushes.Orange;
                case "低":
                case "低风险":
                case "注意":
                    return Brushes.YellowGreen;
                case "无风险":
                case "安全":
                    return Brushes.Green;
                default:
                    return Brushes.Black;
            }
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return Binding.DoNothing;
        }
    }
}