using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;

namespace NetSecurityScanner.Views
{
    public partial class DatabaseSettingsWindow : Window
    {
        private string _settingsPath;
        private string _cncertSettingsPath;
        private DatabaseSettings _settings;

        public DatabaseSettingsWindow()
        {
            InitializeComponent();
            InitializePaths();
            LoadSettings();
            UpdateCncertStatus();
            UpdateLocalLibStatus();
        }

        private void InitializePaths()
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string dbDir = Path.Combine(appDataPath, "NetSecurityScanner");
            Directory.CreateDirectory(dbDir);
            _settingsPath = Path.Combine(dbDir, "update_settings.json");
            _cncertSettingsPath = Path.Combine(dbDir, "cncert_settings.json");
        }

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(_settingsPath))
                {
                    var json = File.ReadAllText(_settingsPath);
                    _settings = JsonSerializer.Deserialize<DatabaseSettings>(json);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DatabaseSettingsWindow] 加载设置失败: {ex.Message}");
                _settings = new DatabaseSettings();
            }

            if (_settings == null)
            {
                _settings = new DatabaseSettings();
            }

            AutoUpdateEnabledCheckBox.IsChecked = _settings.AutoUpdateEnabled;
            UpdateIntervalComboBox.SelectedIndex = GetIntervalIndex(_settings.UpdateIntervalDays);
            AutoUpdateTimeComboBox.SelectedIndex = GetTimeIndex(_settings.AutoUpdateTime);

            CnnvdApiKeyTextBox.Text = _settings.CnnvdApiKey ?? "";
            CnnvdBaseUrlTextBox.Text = _settings.CnnvdBaseUrl ?? "http://www.cnnvd.org.cn";
            CnnvdSyncIntervalTextBox.Text = _settings.CnnvdSyncIntervalDays.ToString();

            // 加载 CNCERT 配置（独立文件）
            LoadCncertSettingsToUi();
        }

        private void LoadCncertSettingsToUi()
        {
            try
            {
                CncertSettings cncert = null;
                if (File.Exists(_cncertSettingsPath))
                {
                    var json = File.ReadAllText(_cncertSettingsPath);
                    cncert = JsonSerializer.Deserialize<CncertSettings>(json);
                }
                if (cncert == null) cncert = new CncertSettings();

                CncertApiKeyTextBox.Text = cncert.ApiKey ?? "";
                CncertBaseUrlTextBox.Text = cncert.BaseUrl ?? "https://www.cert.org.cn";
                CncertApiUrlTextBox.Text = cncert.VulnerabilityApiUrl ?? "https://www.cert.org.cn/api/vulnerability";
                CncertOrgIdTextBox.Text = cncert.OrganizationId ?? "NetSecurityScanner";
                CncertSyncIntervalTextBox.Text = cncert.SyncIntervalDays.ToString();
                CncertTimeoutTextBox.Text = cncert.RequestTimeoutSeconds.ToString();
                CncertPageSizeTextBox.Text = cncert.PageSize.ToString();
                CncertFallbackNvdCheckBox.IsChecked = cncert.EnableFallbackToNvd;
                CncertEnableSyncCheckBox.IsChecked = cncert.EnableAutoSync;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DatabaseSettingsWindow] 加载CNCERT设置失败: {ex.Message}");
            }
        }

        private int GetIntervalIndex(int days)
        {
            return days switch
            {
                1 => 0,
                3 => 1,
                7 => 2,
                15 => 3,
                30 => 4,
                _ => 2
            };
        }

        private int GetTimeIndex(string time)
        {
            return time switch
            {
                "00:00" => 0,
                "02:00" => 1,
                "04:00" => 2,
                "06:00" => 3,
                "08:00" => 4,
                "12:00" => 5,
                "18:00" => 6,
                "22:00" => 7,
                _ => 2
            };
        }

        private int GetIntervalFromIndex(int index)
        {
            return index switch
            {
                0 => 1,
                1 => 3,
                2 => 7,
                3 => 15,
                4 => 30,
                _ => 7
            };
        }

        private string GetTimeFromIndex(int index)
        {
            return index switch
            {
                0 => "00:00",
                1 => "02:00",
                2 => "04:00",
                3 => "06:00",
                4 => "08:00",
                5 => "12:00",
                6 => "18:00",
                7 => "22:00",
                _ => "04:00"
            };
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _settings.AutoUpdateEnabled = AutoUpdateEnabledCheckBox.IsChecked == true;
                _settings.UpdateIntervalDays = GetIntervalFromIndex(UpdateIntervalComboBox.SelectedIndex);
                _settings.AutoUpdateTime = GetTimeFromIndex(AutoUpdateTimeComboBox.SelectedIndex);

                _settings.CnnvdApiKey = CnnvdApiKeyTextBox.Text.Trim();
                _settings.CnnvdBaseUrl = CnnvdBaseUrlTextBox.Text.Trim();
                int.TryParse(CnnvdSyncIntervalTextBox.Text.Trim(), out var cnnvdDays);
                _settings.CnnvdSyncIntervalDays = cnnvdDays > 0 ? cnnvdDays : 7;
                _settings.CncertApiKey = CncertApiKeyTextBox.Text.Trim();

                _settings.IncrementalUpdate = IncrementalUpdateCheckBox.IsChecked == true;
                _settings.AutoBackup = AutoBackupCheckBox.IsChecked == true;
                _settings.NotifyOnComplete = NotifyOnCompleteCheckBox.IsChecked == true;
                _settings.KeepUpdateLog = KeepUpdateLogCheckBox.IsChecked == true;

                var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsPath, json);

                // 单独保存 CNNERT 配置到 CnnvdSyncService
                SaveCnnvdSettings();
                // 单独保存 CNCERT 配置到 CncertSyncService
                SaveCncertSettings();

                MessageBox.Show("设置已保存成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存设置失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveCnnvdSettings()
        {
            try
            {
                var cnnvd = new CnnvdSettings
                {
                    ApiKey = CnnvdApiKeyTextBox.Text.Trim(),
                    BaseUrl = string.IsNullOrWhiteSpace(CnnvdBaseUrlTextBox.Text.Trim()) ? "http://www.cnnvd.org.cn" : CnnvdBaseUrlTextBox.Text.Trim(),
                    EnableAutoSync = true,
                    SyncIntervalDays = int.TryParse(CnnvdSyncIntervalTextBox.Text.Trim(), out var si) && si > 0 ? si : 7,
                    CacheExpiryDays = 7,
                    RequestTimeoutSeconds = 30,
                    UseSystemProxy = false
                };
                CnnvdSyncService.Instance.SaveSettings(cnnvd);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DatabaseSettingsWindow] 保存CNNVD设置失败: {ex.Message}");
            }
        }

        private void SaveCncertSettings()
        {
            try
            {
                var cncert = new CncertSettings
                {
                    ApiKey = CncertApiKeyTextBox.Text.Trim(),
                    BaseUrl = CncertBaseUrlTextBox.Text.Trim(),
                    VulnerabilityApiUrl = CncertApiUrlTextBox.Text.Trim(),
                    OrganizationId = string.IsNullOrWhiteSpace(CncertOrgIdTextBox.Text.Trim()) ? "NetSecurityScanner" : CncertOrgIdTextBox.Text.Trim(),
                    SyncIntervalDays = int.TryParse(CncertSyncIntervalTextBox.Text.Trim(), out var si) && si > 0 ? si : 7,
                    CacheExpiryDays = 7,
                    RequestTimeoutSeconds = int.TryParse(CncertTimeoutTextBox.Text.Trim(), out var rt) && rt > 0 ? rt : 30,
                    PageSize = int.TryParse(CncertPageSizeTextBox.Text.Trim(), out var ps) && ps > 0 ? ps : 100,
                    StartPage = 1,
                    EnableFallbackToNvd = CncertFallbackNvdCheckBox.IsChecked == true,
                    EnableAutoSync = CncertEnableSyncCheckBox.IsChecked == true,
                    UseSystemProxy = false,
                    IncludeHighRiskAdvisory = true,
                    IncludeVulnerabilityAlert = true
                };
                CncertSyncService.Instance.SaveSettings(cncert);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DatabaseSettingsWindow] 保存CNCERT设置失败: {ex.Message}");
            }
        }

        private async void TestCncertButton_Click(object sender, RoutedEventArgs e)
        {
            TestCncertButton.IsEnabled = false;
            CncertStatusText.Text = "状态：正在测试连接...";
            CncertStatusText.Foreground = System.Windows.Media.Brushes.DodgerBlue;
            try
            {
                SaveCncertSettings();
                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(10));
                var service = CncertSyncService.Instance;
                await service.InitializeAsync(cts.Token);
                var stats = service.GetStatistics();
                int total = 0;
                if (stats != null && stats.ContainsKey("Total")) total = stats["Total"];
                CncertStatusText.Text = $"状态：连接成功，当前共 {total} 个漏洞条目（最近同步：{(service.LastSyncTime.HasValue ? service.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "未同步")}）";
                CncertStatusText.Foreground = System.Windows.Media.Brushes.SeaGreen;
            }
            catch (Exception ex)
            {
                CncertStatusText.Text = $"状态：连接失败 - {ex.Message}";
                CncertStatusText.Foreground = System.Windows.Media.Brushes.IndianRed;
            }
            finally
            {
                TestCncertButton.IsEnabled = true;
            }
        }

        private async void SyncCncertNowButton_Click(object sender, RoutedEventArgs e)
        {
            SyncCncertNowButton.IsEnabled = false;
            CncertStatusText.Text = "状态：正在同步...";
            CncertStatusText.Foreground = System.Windows.Media.Brushes.DodgerBlue;
            try
            {
                SaveCncertSettings();
                var service = CncertSyncService.Instance;
                var ok = await service.SyncAsync();
                if (ok)
                {
                    var stats = service.GetStatistics();
                    int total = 0;
                    if (stats != null && stats.ContainsKey("Total")) total = stats["Total"];
                    CncertStatusText.Text = $"状态：同步成功，共 {total} 个漏洞（同步时间：{service.LastSyncTime:yyyy-MM-dd HH:mm:ss}）";
                    CncertStatusText.Foreground = System.Windows.Media.Brushes.SeaGreen;
                    MessageBox.Show($"CNCERT 漏洞库同步完成！\n当前总数：{total}\n同步时间：{service.LastSyncTime:yyyy-MM-dd HH:mm:ss}",
                        "同步成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    CncertStatusText.Text = "状态：同步失败，已使用内置数据回退";
                    CncertStatusText.Foreground = System.Windows.Media.Brushes.DarkOrange;
                    MessageBox.Show("同步失败，但已使用内置数据兜底，请检查网络和API Key配置。", "同步失败", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                CncertStatusText.Text = $"状态：同步异常 - {ex.Message}";
                CncertStatusText.Foreground = System.Windows.Media.Brushes.IndianRed;
                MessageBox.Show($"同步异常：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SyncCncertNowButton.IsEnabled = true;
            }
        }

        private void CncertStatsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var service = CncertSyncService.Instance;
                var stats = service.GetStatistics();
                var sb = new System.Text.StringBuilder();
                int total = 0, criticalHigh = 0, mid = 0, low = 0;
                if (stats != null)
                {
                    if (stats.ContainsKey("Total")) total = stats["Total"];
                    if (stats.ContainsKey("超危")) criticalHigh += stats["超危"];
                    if (stats.ContainsKey("高危")) criticalHigh += stats["高危"];
                    if (stats.ContainsKey("中危")) mid = stats["中危"];
                    if (stats.ContainsKey("低危")) low = stats["低危"];
                }
                sb.AppendLine("CNCERT 漏洞库统计：");
                sb.AppendLine($"  总计：{total}");
                sb.AppendLine($"  超危/高危：{criticalHigh}");
                sb.AppendLine($"  中危：{mid}");
                sb.AppendLine($"  低危：{low}");
                if (service.LastSyncTime.HasValue)
                    sb.AppendLine($"  上次同步：{service.LastSyncTime.Value:yyyy-MM-dd HH:mm:ss}");
                else
                    sb.AppendLine("  上次同步：未同步");
                MessageBox.Show(sb.ToString(), "CNCERT 统计", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"获取统计失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateCncertStatus()
        {
            try
            {
                var service = CncertSyncService.Instance;
                if (service.IsInitialized)
                {
                    var total = service.GetAll().Count;
                    CncertStatusText.Text = $"状态：已初始化（{total} 个漏洞）";
                    CncertStatusText.Foreground = System.Windows.Media.Brushes.SeaGreen;
                }
                else
                {
                    CncertStatusText.Text = "状态：未连接（点击测试连接或立即同步）";
                    CncertStatusText.Foreground = System.Windows.Media.Brushes.Gray;
                }
            }
            catch (Exception ex)
            {
                CncertStatusText.Text = $"状态：异常 - {ex.Message}";
                CncertStatusText.Foreground = System.Windows.Media.Brushes.IndianRed;
            }
        }

        private void UpdateLocalLibStatus()
        {
            try
            {
                var lib = LocalVulnerabilityLibrary.Instance;
                if (lib == null)
                {
                    LocalLibStatusText.Text = "状态：本地库未初始化";
                    LocalLibStatusText.Foreground = System.Windows.Media.Brushes.Gray;
                    return;
                }

                if (!lib.IsLoaded)
                {
                    try { lib.LoadCurrentAsync().GetAwaiter().GetResult(); } catch { /* ignore */ }
                }

                var meta = lib.GetMeta();
                if (meta == null || meta.TotalCount == 0)
                {
                    LocalLibStatusText.Text = $"状态：本地库为空（目录：{lib.CurrentPath}）";
                    LocalLibStatusText.Foreground = System.Windows.Media.Brushes.DarkOrange;
                }
                else
                {
                    var lastSync = meta.LastSyncTime.HasValue ? meta.LastSyncTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "未同步";
                    var sources = meta.Sources != null && meta.Sources.Count > 0
                        ? string.Join("/", meta.Sources.Keys)
                        : "-";
                    LocalLibStatusText.Text = $"状态：v{meta.Version}  共 {meta.TotalCount} 条  来源 {sources}  同步 {lastSync}";
                    LocalLibStatusText.Foreground = System.Windows.Media.Brushes.SeaGreen;
                }
            }
            catch (Exception ex)
            {
                LocalLibStatusText.Text = $"状态：异常 - {ex.Message}";
                LocalLibStatusText.Foreground = System.Windows.Media.Brushes.IndianRed;
            }
        }

        #region 本地 JSON 漏洞库运维（auto-save-vulnerability-json-library）

        private async void ForceSaveButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var confirm = MessageBox.Show("将覆盖当前 JSON 漏洞库，是否继续？\n（自动合并 CNNVD + CNCERT 内存数据）",
                    "确认入库", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (confirm != MessageBoxResult.Yes) return;

                ForceSaveButton.IsEnabled = false;
                LocalLibStatusText.Text = "状态：正在合并并入库...";
                LocalLibStatusText.Foreground = System.Windows.Media.Brushes.DodgerBlue;

                // 1) 先同步两个源（确保内存有最新数据）
                var allEntries = new List<NetSecurityScanner.Models.LocalVulnerabilityEntry>();

                try
                {
                    var cnnvd = CnnvdSyncService.Instance;
                    await cnnvd.InitializeAsync();
                    var cnnvdList = LocalVulnerabilityConverter.FromCnnvdList(cnnvd.GetAll());
                    allEntries.AddRange(cnnvdList);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[ForceSave] CNNVD 拉取失败: {ex.Message}");
                }

                try
                {
                    var cncert = CncertSyncService.Instance;
                    await cncert.InitializeAsync();
                    var cncertList = LocalVulnerabilityConverter.FromCncertList(cncert.GetAll());
                    allEntries.AddRange(cncertList);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[ForceSave] CNCERT 拉取失败: {ex.Message}");
                }

                // 2) ForceFlush 到本地库
                var lib = LocalVulnerabilityLibrary.Instance;
                var (ok, msg) = await lib.ForceFlushAsync(allEntries, "Manual", System.Threading.CancellationToken.None);

                if (ok)
                {
                    MessageBox.Show($"已写入 {allEntries.Count} 条漏洞到本地 JSON 库。\n{msg}", "入库成功", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"入库失败：{msg}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                UpdateLocalLibStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"立即入库异常：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                ForceSaveButton.IsEnabled = true;
            }
        }

        private void OpenLibraryFolderButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var lib = LocalVulnerabilityLibrary.Instance;
                var dir = lib?.CurrentPath;
                if (string.IsNullOrEmpty(dir) || !System.IO.Directory.Exists(dir))
                {
                    MessageBox.Show("本地库尚未建立，请先执行同步或点击【立即入库】。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                System.Diagnostics.Process.Start("explorer.exe", dir);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"打开目录失败：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ManageLibraryButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var lib = LocalVulnerabilityLibrary.Instance;
                if (lib == null) return;

                var snapshots = lib.ListSnapshots();
                var meta = lib.GetMeta();

                var dlg = new LocalLibraryManagerWindow(snapshots, meta);
                dlg.Owner = this;
                var result = dlg.ShowDialog();
                if (result == true)
                {
                    if (dlg.SelectedAction == LocalLibraryManagerWindow.Action.ClearLibrary)
                    {
                        var confirm = MessageBox.Show("确定要清空本地 JSON 漏洞库吗？\n（清空前会自动归档为快照）",
                            "二次确认", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                        if (confirm == MessageBoxResult.Yes)
                        {
                            var (ok, msg) = await lib.ClearAsync();
                            MessageBox.Show(msg, ok ? "已清空" : "错误", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Error);
                        }
                    }
                    else if (dlg.SelectedAction == LocalLibraryManagerWindow.Action.Rollback && !string.IsNullOrEmpty(dlg.SelectedSnapshot))
                    {
                        var confirm = MessageBox.Show($"确定回滚到快照 [{dlg.SelectedSnapshot}] 吗？\n（当前库将自动归档）",
                            "二次确认", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                        if (confirm == MessageBoxResult.Yes)
                        {
                            var (ok, msg) = await lib.RollbackAsync(dlg.SelectedSnapshot);
                            MessageBox.Show(msg, ok ? "已回滚" : "错误", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Error);
                        }
                    }
                    UpdateLocalLibStatus();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"库管理操作异常：{ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void ResetButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("确定要恢复默认设置吗？", "确认", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _settings = new DatabaseSettings();
                AutoUpdateEnabledCheckBox.IsChecked = _settings.AutoUpdateEnabled;
                UpdateIntervalComboBox.SelectedIndex = 2;
                AutoUpdateTimeComboBox.SelectedIndex = 2;
                CnnvdApiKeyTextBox.Text = "";
                CnnvdBaseUrlTextBox.Text = "http://www.cnnvd.org.cn";
                CnnvdSyncIntervalTextBox.Text = "7";

                CncertApiKeyTextBox.Text = "";
                CncertBaseUrlTextBox.Text = "https://www.cert.org.cn";
                CncertApiUrlTextBox.Text = "https://www.cert.org.cn/api/vulnerability";
                CncertOrgIdTextBox.Text = "NetSecurityScanner";
                CncertSyncIntervalTextBox.Text = "7";
                CncertTimeoutTextBox.Text = "30";
                CncertPageSizeTextBox.Text = "100";
                CncertFallbackNvdCheckBox.IsChecked = true;
                CncertEnableSyncCheckBox.IsChecked = true;

                IncrementalUpdateCheckBox.IsChecked = false;
                AutoBackupCheckBox.IsChecked = true;
                NotifyOnCompleteCheckBox.IsChecked = true;
                KeepUpdateLogCheckBox.IsChecked = true;

                MessageBox.Show("已恢复默认设置，请点击保存按钮应用更改", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }

    public class DatabaseSettings
    {
        public bool AutoUpdateEnabled { get; set; } = false;
        public int UpdateIntervalDays { get; set; } = 7;
        public string AutoUpdateTime { get; set; } = "04:00";
        public string CnnvdApiKey { get; set; } = "";
        public string CnnvdBaseUrl { get; set; } = "http://www.cnnvd.org.cn";
        public int CnnvdSyncIntervalDays { get; set; } = 7;
        public string CncertApiKey { get; set; } = "";
        public bool IncrementalUpdate { get; set; } = false;
        public bool AutoBackup { get; set; } = true;
        public bool NotifyOnComplete { get; set; } = true;
        public bool KeepUpdateLog { get; set; } = true;
    }
}
