using System;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AssetDetailWindow : Window
    {
        public AssetDetailWindow(Asset asset)
        {
            InitializeComponent();
            if (asset == null)
            {
                Title = "资产详情";
                return;
            }
            Title = $"资产详情 - {asset.Name}";
            TitleText.Text = $"资产详情 - {asset.Name}";

            NameText.Text = asset.Name ?? "-";
            IPAddressText.Text = asset.IPAddress ?? "-";
            MacAddressText.Text = string.IsNullOrWhiteSpace(asset.MacAddress) ? "-" : asset.MacAddress;
            AssetTypeText.Text = string.IsNullOrWhiteSpace(asset.AssetType) ? "-" : asset.AssetType;
            OperatingSystemText.Text = string.IsNullOrWhiteSpace(asset.OperatingSystem) ? "-" : asset.OperatingSystem;
            DepartmentText.Text = string.IsNullOrWhiteSpace(asset.Department) ? "-" : asset.Department;
            OwnerText.Text = string.IsNullOrWhiteSpace(asset.Owner) ? "-" : asset.Owner;
            LocationText.Text = string.IsNullOrWhiteSpace(asset.Location) ? "-" : asset.Location;

            StatusText.Text = asset.Status.ToString();
            StatusText.Foreground = asset.Status switch
            {
                AssetStatus.Online => (Brush)new BrushConverter().ConvertFromString("#00b894")!,
                AssetStatus.Offline => (Brush)new BrushConverter().ConvertFromString("#e74c3c")!,
                AssetStatus.Maintenance => (Brush)new BrushConverter().ConvertFromString("#fdcb6e")!,
                AssetStatus.Retired => (Brush)new BrushConverter().ConvertFromString("#95a5a6")!,
                _ => (Brush)new BrushConverter().ConvertFromString("#2d3436")!
            };

            TagsText.Text = (asset.Tags == null || asset.Tags.Count == 0)
                ? "-"
                : string.Join(", ", asset.Tags);
            DescriptionText.Text = string.IsNullOrWhiteSpace(asset.Description) ? "-" : asset.Description;
            CreatedAtText.Text = asset.CreatedAt == default ? "-" : asset.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss");
            CreatedByText.Text = string.IsNullOrWhiteSpace(asset.CreatedBy) ? "-" : asset.CreatedBy;
            LastModifiedText.Text = asset.LastModified == default ? "-" : asset.LastModified.ToString("yyyy-MM-dd HH:mm:ss");
            LastModifiedByText.Text = string.IsNullOrWhiteSpace(asset.LastModifiedBy) ? "-" : asset.LastModifiedBy;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
