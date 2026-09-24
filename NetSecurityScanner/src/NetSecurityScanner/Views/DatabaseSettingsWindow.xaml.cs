using System;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace NetSecurityScanner.Views
{
    public partial class DatabaseSettingsWindow : Window
    {
        private string _settingsPath;
        private DatabaseSettings _settings;

        public DatabaseSettingsWindow()
        {
            InitializeComponent();
            InitializePaths();
            LoadSettings();
        }

        private void InitializePaths()
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string dbDir = Path.Combine(appDataPath, "NetSecurityScanner");
            Directory.CreateDirectory(dbDir);
            _settingsPath = Path.Combine(dbDir, "update_settings.json");
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
            CncertApiKeyTextBox.Text = _settings.CncertApiKey ?? "";
            
            IncrementalUpdateCheckBox.IsChecked = _settings.IncrementalUpdate;
            AutoBackupCheckBox.IsChecked = _settings.AutoBackup;
            NotifyOnCompleteCheckBox.IsChecked = _settings.NotifyOnComplete;
            KeepUpdateLogCheckBox.IsChecked = _settings.KeepUpdateLog;
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
                _settings.CncertApiKey = CncertApiKeyTextBox.Text.Trim();
                
                _settings.IncrementalUpdate = IncrementalUpdateCheckBox.IsChecked == true;
                _settings.AutoBackup = AutoBackupCheckBox.IsChecked == true;
                _settings.NotifyOnComplete = NotifyOnCompleteCheckBox.IsChecked == true;
                _settings.KeepUpdateLog = KeepUpdateLogCheckBox.IsChecked == true;

                var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsPath, json);

                MessageBox.Show("设置已保存成功！", "成功", MessageBoxButton.OK, MessageBoxImage.Information);
                DialogResult = true;
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"保存设置失败: {ex.Message}", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

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
                CncertApiKeyTextBox.Text = "";
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
        public string CncertApiKey { get; set; } = "";
        public bool IncrementalUpdate { get; set; } = false;
        public bool AutoBackup { get; set; } = true;
        public bool NotifyOnComplete { get; set; } = true;
        public bool KeepUpdateLog { get; set; } = true;
    }
}
