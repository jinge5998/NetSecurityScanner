using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using Microsoft.Win32;
using NetSecurityScanner.Models;
using NetSecurityScanner.Services;
using NetSecurityScanner.Utils;

namespace NetSecurityScanner.Views
{
  public partial class LicenseCodeGeneratorWindow : Window
  {
    private readonly LicenseIssuerStore _store;
    private List<LicenseIssuanceRecord> _records = new();

    private static readonly string HmacKey = "NSS2026Hmac!@#Lic";

    public LicenseCodeGeneratorWindow()
    {
      InitializeComponent();
      _store = new LicenseIssuerStore();
      Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
      try
      {
        string machineId = MachineFingerprint.Generate();
        FullMachineIdTextBox.Text = machineId;
        string prefix = ComputeMachineHash(machineId);
        CurrentMachineIdText.Text = $"本机前缀: {prefix}";
        FullMachineIdPrefixHint.Text = $"本机完整前缀: {prefix}（填入左侧目标机器码）";

        IssuerTextBox.Text = Environment.UserName;
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"⚠️ 读取本机指纹失败: {ex.Message}";
      }

      RefreshHistory();
    }

    private void MachineIdPrefixTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
      string prefix = MachineIdPrefixTextBox.Text.ToUpper();
      MachineIdPrefixTextBox.Text = prefix;
      MachineIdPrefixTextBox.SelectionStart = prefix.Length;

      ValidatePrefix(prefix);
    }

    private void ValidatePrefix(string prefix)
    {
      if (string.IsNullOrEmpty(prefix))
      {
        MachineIdHintText.Text = "填入授权目标机器的机器码前8位（大写字母/数字）";
        MachineIdHintText.Foreground = new System.Windows.Media.SolidColorBrush(
            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#b2bec3"));
        return;
      }

      if (prefix.Length < 8)
      {
        MachineIdHintText.Text = $"还需 {8 - prefix.Length} 个字符";
        MachineIdHintText.Foreground = new System.Windows.Media.SolidColorBrush(
            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#fdcb6e"));
      }
      else
      {
        MachineIdHintText.Text = "✅ 机器码前缀已完整";
        MachineIdHintText.Foreground = new System.Windows.Media.SolidColorBrush(
            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"));
      }
    }

    private void ReadCurrentMachineButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        string machineId = MachineFingerprint.Generate();
        string prefix = ComputeMachineHash(machineId);
        MachineIdPrefixTextBox.Text = prefix;
        FullMachineIdTextBox.Text = machineId;
        StatusTextBlock.Text = $"✅ 已读取本机机器码: {machineId}";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"⚠️ 读取失败: {ex.Message}";
      }
    }

    private void LicenseTypeRadio_Changed(object sender, RoutedEventArgs e)
    {
    }

    private void GenerateButton_Click(object sender, RoutedEventArgs e)
    {
      GenerateErrorText.Text = "";
      string prefix = MachineIdPrefixTextBox.Text.Trim().ToUpper();

      if (string.IsNullOrEmpty(prefix) || prefix.Length < 8)
      {
        GenerateErrorText.Text = "❌ 请输入完整的目标机器码前缀（8位）";
        return;
      }

      if (!Regex.IsMatch(prefix, @"^[A-F0-9]{8}$"))
      {
        GenerateErrorText.Text = "❌ 机器码前缀只能包含大写字母 A-F 和数字 0-9";
        return;
      }

      if (!IssueDatePicker.SelectedDate.HasValue)
      {
        GenerateErrorText.Text = "❌ 请选择发行日期";
        return;
      }

      if (!TimeSpan.TryParse(IssueTimeTextBox.Text.Trim(), out var timeSpan))
      {
        GenerateErrorText.Text = "❌ 时间格式无效，请使用 HH:mm:ss 格式";
        return;
      }

      var issueTime = IssueDatePicker.SelectedDate.Value.Date.Add(timeSpan);
      if (issueTime > DateTime.Now.AddMinutes(5))
      {
        GenerateErrorText.Text = "❌ 发行时间不能超过当前时间+5分钟";
        return;
      }

      LicenseType licenseType = GetSelectedLicenseType();
      string typeCode = LicenseInfo.TypeToCode(licenseType);
      string timestampStr = issueTime.ToString("yyyyMMddHHmmss");

      string dataToSign = $"{prefix}-{timestampStr}-{typeCode}";
      string hmacCode = GenerateHmac(dataToSign, HmacKey);

      string licenseCode = $"{prefix}-{timestampStr}-{typeCode}-{hmacCode}";
      GeneratedCodeTextBox.Text = licenseCode;

      RunLocalValidation(prefix, timestampStr, typeCode, hmacCode, licenseType, issueTime);

      StatusTextBlock.Text = $"✅ 授权码生成成功 | 类型: {LicenseInfo.TypeToCode(licenseType)} | 发行时间: {issueTime:yyyy-MM-dd HH:mm}";
    }

    private void RunLocalValidation(string prefix, string timestamp, string typeCode, string hmacCode,
        LicenseType licenseType, DateTime issueTime)
    {
      string dataToVerify = $"{prefix}-{timestamp}-{typeCode}";
      bool hmacOk = VerifyHmac(dataToVerify, hmacCode, HmacKey);

      string currentMachineId;
      try { currentMachineId = MachineFingerprint.Generate(); }
      catch { currentMachineId = ""; }
      string currentPrefix = ComputeMachineHash(currentMachineId);
      bool machineMatch = string.Equals(prefix, currentPrefix, StringComparison.OrdinalIgnoreCase);

      DateTime? expiry = GetExpiryTime(licenseType, issueTime);
      string expiryDisplay = expiry?.ToString("yyyy-MM-dd HH:mm") ?? "永久";

      ValidateHmac.Text = hmacOk ? "✅ 通过" : "❌ 失败";
      ValidateHmac.Foreground = hmacOk
          ? new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"))
          : new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#d63031"));

      ValidateMachineMatch.Text = machineMatch ? "✅ 本机匹配" : "⚠️ 不匹配（正常，跨机器激活会这样）";
      ValidateMachineMatch.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"));

      ValidateExpiry.Text = expiryDisplay;
      ValidateType.Text = LicenseInfo.TypeToCode(licenseType) switch
      {
        "T" => "🕐 试用（5分钟）",
        "1" => "📅 1年期",
        "2" => "🗓️ 2年期",
        "P" => "♾️ 永久授权",
        _ => typeCode
      };
    }

    private LicenseType GetSelectedLicenseType()
    {
      if (TrialRadio.IsChecked == true) return LicenseType.TRIAL;
      if (Year1Radio.IsChecked == true) return LicenseType.YEAR1;
      if (Year2Radio.IsChecked == true) return LicenseType.YEAR2;
      if (PermanentRadio.IsChecked == true) return LicenseType.PERMANENT;
      return LicenseType.TRIAL;
    }

    private void SaveAndRecordButton_Click(object sender, RoutedEventArgs e)
    {
      string code = GeneratedCodeTextBox.Text.Trim();
      if (string.IsNullOrEmpty(code) || !code.Contains('-'))
      {
        StatusTextBlock.Text = "⚠️ 请先生成授权码";
        return;
      }

      try
      {
        string prefix = MachineIdPrefixTextBox.Text.Trim().ToUpper();
        string timestampStr = IssueTimeTextBox.Text;
        if (!DateTime.TryParse(IssueTimeTextBox.Text, out _))
        {
          var date = IssueDatePicker.SelectedDate ?? DateTime.Now;
          var time = TimeSpan.Parse(IssueTimeTextBox.Text);
          timestampStr = date.Add(time).ToString("yyyyMMddHHmmss");
        }
        else
        {
          timestampStr = IssueDatePicker.SelectedDate?.ToString("yyyyMMdd") ?? DateTime.Now.ToString("yyyyMMdd");
          timestampStr += IssueTimeTextBox.Text.Replace(":", "");
        }

        var parts = code.Split('-');
        string typeCode = parts[2].ToUpper();
        LicenseType licenseType = LicenseInfo.CodeToType(typeCode);

        DateTime issueTime;
        if (parts.Length >= 2 && DateTime.TryParseExact(parts[1], "yyyyMMddHHmmss", null,
            System.Globalization.DateTimeStyles.None, out var parsedTime))
        {
          issueTime = parsedTime;
        }
        else
        {
          issueTime = DateTime.Now;
        }

        var record = new LicenseIssuanceRecord
        {
          LicenseCode = code,
          MachineId = FullMachineIdTextBox.Text,
          MachineIdPrefix = prefix,
          LicenseType = licenseType,
          IssuedTime = issueTime,
          ExpiryTime = GetExpiryTime(licenseType, issueTime),
          IssuedBy = IssuerTextBox.Text.Trim(),
          Note = NoteTextBox.Text.Trim()
        };

        _store.AddRecord(record);
        RefreshHistory();
        StatusTextBlock.Text = $"✅ 记录已保存 | 共 {_records.Count} 条历史记录";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"⚠️ 保存失败: {ex.Message}";
      }
    }

    private void ClearResultButton_Click(object sender, RoutedEventArgs e)
    {
      GeneratedCodeTextBox.Text = "";
      ValidateHmac.Text = "—";
      ValidateMachineMatch.Text = "—";
      ValidateExpiry.Text = "—";
      ValidateType.Text = "—";
      ValidateHmac.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#636e72"));
      ValidateMachineMatch.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#636e74"));
      StatusTextBlock.Text = "已清空结果（授权码仍保留在左侧输入框）";
    }

    private void CopyCodeButton_Click(object sender, RoutedEventArgs e)
    {
      string code = GeneratedCodeTextBox.Text;
      if (string.IsNullOrEmpty(code))
      {
        StatusTextBlock.Text = "⚠️ 没有可复制的授权码";
        return;
      }
      try
      {
        Clipboard.SetText(code);
        StatusTextBlock.Text = $"✅ 授权码已复制到剪贴板";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"⚠️ 复制失败: {ex.Message}";
      }
    }

    private void CopyHistoryCode_Click(object sender, RoutedEventArgs e)
    {
      if (sender is Button btn && btn.Tag is LicenseIssuanceRecord record)
      {
        try
        {
          Clipboard.SetText(record.LicenseCode);
          StatusTextBlock.Text = $"✅ 已复制: {record.LicenseCode}";
        }
        catch (Exception ex)
        {
          StatusTextBlock.Text = $"⚠️ 复制失败: {ex.Message}";
        }
      }
    }

    private void DeleteHistoryRecord_Click(object sender, RoutedEventArgs e)
    {
      if (sender is Button btn && btn.Tag is LicenseIssuanceRecord record)
      {
        var confirm = MessageBox.Show(
            $"确定删除此发行记录？\n\n授权码: {record.LicenseCode}\n类型: {record.LicenseTypeName}",
            "确认删除", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (confirm == MessageBoxResult.Yes)
        {
          _store.RemoveRecord(record.Id);
          RefreshHistory();
          StatusTextBlock.Text = $"✅ 记录已删除";
        }
      }
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
      RefreshHistory();
      StatusTextBlock.Text = $"✅ 已刷新 | 共 {_records.Count} 条记录";
    }

    private void ClearHistoryButton_Click(object sender, RoutedEventArgs e)
    {
      var confirm = MessageBox.Show(
          "确定清空所有发行记录？此操作不可恢复！",
          "确认清空", MessageBoxButton.YesNo, MessageBoxImage.Warning);

      if (confirm == MessageBoxResult.Yes)
      {
        _store.ClearAllRecords();
        RefreshHistory();
        StatusTextBlock.Text = "✅ 历史记录已清空";
      }
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
      if (_records.Count == 0)
      {
        StatusTextBlock.Text = "⚠️ 没有可导出的记录";
        return;
      }

      var dialog = new SaveFileDialog
      {
        Filter = "CSV 文件 (*.csv)|*.csv",
        FileName = $"license_issuance_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
        Title = "导出授权码发行记录"
      };

      if (dialog.ShowDialog() == true)
      {
        try
        {
          var csv = _store.ExportRecordsToCsv(_records);
          File.WriteAllText(dialog.FileName, csv, Encoding.UTF8);
          StatusTextBlock.Text = $"✅ 已导出到: {dialog.FileName}";
        }
        catch (Exception ex)
        {
          StatusTextBlock.Text = $"⚠️ 导出失败: {ex.Message}";
        }
      }
    }

    private void RefreshHistory()
    {
      _records = _store.GetAllRecords();
      HistoryDataGrid.ItemsSource = null;
      HistoryDataGrid.ItemsSource = _records;
      HistoryCountText.Text = $"共 {_records.Count} 条记录";
    }

    private DateTime? GetExpiryTime(LicenseType type, DateTime issuedTime)
    {
      return type switch
      {
        LicenseType.TRIAL => issuedTime.AddMinutes(5),
        LicenseType.YEAR1 => issuedTime.AddYears(1),
        LicenseType.YEAR2 => issuedTime.AddYears(2),
        LicenseType.PERMANENT => null,
        _ => issuedTime
      };
    }

    private static string ComputeMachineHash(string machineId)
    {
      using var sha256 = SHA256.Create();
      byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
      var sb = new StringBuilder();
      for (int i = 0; i < 8; i++)
      {
        sb.Append(hash[i].ToString("X2"));
      }
      return sb.ToString().ToUpper();
    }

    private static string GenerateHmac(string data, string key)
    {
      using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
      byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
      var sb = new StringBuilder();
      for (int i = 0; i < 3; i++)
      {
        sb.Append(hash[i].ToString("X2"));
      }
      return sb.ToString();
    }

    private static bool VerifyHmac(string data, string hmacCode, string key)
    {
      string expected = GenerateHmac(data, key);
      return string.Equals(expected, hmacCode, StringComparison.OrdinalIgnoreCase);
    }
  }
}