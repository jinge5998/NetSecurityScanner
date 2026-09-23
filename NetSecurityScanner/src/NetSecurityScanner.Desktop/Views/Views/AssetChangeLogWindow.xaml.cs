using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class AssetChangeLogWindow : Window
    {
        private readonly AssetManagementService _assetService;
        private List<AssetChangeLog> _allLogs;
        private List<Asset> _allAssets;

        public AssetChangeLogWindow()
        {
            InitializeComponent();
            _assetService = new AssetManagementService();
            Loaded += AssetChangeLogWindow_Loaded;
        }

        private void AssetChangeLogWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _allLogs = _assetService.GetAllChangeLogs();
            _allAssets = _assetService.GetAllAssets();

            // 资产筛选下拉
            var items = new List<Asset> { new Asset { Id = "", Name = "（全部资产）" } };
            items.AddRange(_allAssets);
            AssetFilterCombo.ItemsSource = items;
            AssetFilterCombo.SelectedIndex = 0;

            ApplyFilter();
        }

        private void AssetFilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!IsLoaded) return;
            ApplyFilter();
        }

        private void ClearFilterButton_Click(object sender, RoutedEventArgs e)
        {
            AssetFilterCombo.SelectedIndex = 0;
        }

        private void ApplyFilter()
        {
            if (_allLogs == null) return;

            var selected = AssetFilterCombo.SelectedItem as Asset;
            string assetId = selected?.Id ?? "";
            IEnumerable<AssetChangeLog> q = _allLogs;
            if (!string.IsNullOrEmpty(assetId))
                q = q.Where(l => l.AssetId == assetId);

            var list = q.ToList();
            ChangeLogDataGrid.ItemsSource = list;
            SummaryText.Text = $"共 {list.Count} 条记录" + (string.IsNullOrEmpty(assetId) ? "" : $"（已按资产过滤）");
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
