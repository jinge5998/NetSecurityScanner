using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
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
        TargetMachineIdTextBox.Text = machineId;
        string prefix = ComputeMachineHash(machineId);
        CurrentMachineIdText.Text = $"本机前缀: {prefix}";

        IssuerTextBox.Text = Environment.UserName;
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"\u26a0\ufe0f 读取本机指纹失败: {ex.Message}";
      }

      // 发行时间默认取当前时间（避免硬编码导致超出 now+5min 校验限制）
      SetIssueTimeToNow();

      RefreshHistory();
    }

    private void NowTimeButton_Click(object sender, RoutedEventArgs e)
    {
      SetIssueTimeToNow();
      StatusTextBlock.Text = "\u2705 发行时间已刷新为当前时间";
    }

    private void SetIssueTimeToNow()
    {
      IssueDatePicker.SelectedDate = DateTime.Now.Date;
      IssueTimeTextBox.Text = DateTime.Now.ToString("HH:mm:ss");
    }

    private void TargetMachineIdTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
      string machineId = TargetMachineIdTextBox.Text.Trim().ToUpperInvariant();
      if (TargetMachineIdTextBox.Text != machineId)
      {
        TargetMachineIdTextBox.Text = machineId;
        TargetMachineIdTextBox.SelectionStart = machineId.Length;
        return; // 赋值后 TextChanged 会再次触发并完成校验
      }

      ValidateMachineId(machineId);
    }

    /// <summary>校验完整机器码（32位十六进制）并实时计算绑定前缀</summary>
    private void ValidateMachineId(string machineId)
    {
      SetHintColor("#b2bec3");

      if (string.IsNullOrEmpty(machineId))
      {
        MachineIdHintText.Text = "粘贴授权目标机器的完整机器码（32位大写十六进制）";
        ComputedPrefixText.Text = "—";
        ComputedPrefixText.Foreground = new System.Windows.Media.SolidColorBrush(
            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#636e72"));
        return;
      }

      if (!Regex.IsMatch(machineId, @"^[0-9A-F]+$"))
      {
        MachineIdHintText.Text = "\u274c 机器码只能包含十六进制字符（0-9、A-F）";
        SetHintColor("#d63031");
        ComputedPrefixText.Text = "—";
        return;
      }

      if (machineId.Length < 32)
      {
        MachineIdHintText.Text = $"还需 {32 - machineId.Length} 个字符（当前 {machineId.Length}/32）";
        SetHintColor("#fdcb6e");
        ComputedPrefixText.Text = "—";
        return;
      }

      // 32 位完整机器码：计算绑定前缀
      string prefix = ComputeMachineHash(machineId);
      ComputedPrefixText.Text = prefix;
      ComputedPrefixText.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"));
      MachineIdHintText.Text = "\u2705 机器码有效，授权码将绑定此机器";
      SetHintColor("#00b894");
    }

    private void SetHintColor(string colorHex)
    {
      MachineIdHintText.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(colorHex));
    }

    private void ReadCurrentMachineButton_Click(object sender, RoutedEventArgs e)
    {
      try
      {
        string machineId = MachineFingerprint.Generate();
        TargetMachineIdTextBox.Text = machineId;
        StatusTextBlock.Text = $"\u2705 已填入本机机器码: {machineId}";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"\u26a0\ufe0f 读取失败: {ex.Message}";
      }
    }

    private void LicenseTypeRadio_Changed(object sender, RoutedEventArgs e)
    {
    }

    private void GenerateButton_Click(object sender, RoutedEventArgs e)
    {
      GenerateErrorText.Text = "";
      string machineId = TargetMachineIdTextBox.Text.Trim().ToUpperInvariant();

      if (string.IsNullOrEmpty(machineId))
      {
        GenerateErrorText.Text = "\u274c 请填入目标机器的完整机器码（32位）";
        return;
      }

      if (machineId.Length != 32 || !Regex.IsMatch(machineId, @"^[0-9A-F]{32}$"))
      {
        GenerateErrorText.Text = "\u274c 完整机器码必须为 32 位十六进制字符（0-9、A-F）";
        return;
      }

      // 核心规则：授权码基于完整机器码计算的绑定前缀生成
      string prefix = ComputeMachineHash(machineId);

      if (!IssueDatePicker.SelectedDate.HasValue)
      {
        GenerateErrorText.Text = "\u274c 请选择发行日期";
        return;
      }

      if (!TimeSpan.TryParse(IssueTimeTextBox.Text.Trim(), out var timeSpan))
      {
        GenerateErrorText.Text = "\u274c 时间格式无效，请使用 HH:mm:ss 格式";
        return;
      }

      var issueTime = IssueDatePicker.SelectedDate.Value.Date.Add(timeSpan);
      if (issueTime > DateTime.Now.AddMinutes(5))
      {
        GenerateErrorText.Text = "\u274c 发行时间不能超过当前时间+5分钟";
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

      StatusTextBlock.Text = $"\u2705 授权码生成成功 | 绑定前缀: {prefix} | 类型: {typeCode} | 发行时间: {issueTime:yyyy-MM-dd HH:mm}";
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

      ValidateHmac.Text = hmacOk ? "\u2705 通过" : "\u274c 失败";
      ValidateHmac.Foreground = hmacOk
          ? new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"))
          : new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#d63031"));

      ValidateMachineMatch.Text = machineMatch ? "\u2705 本机匹配" : "\u26a0\ufe0f 不匹配（正常，跨机器激活会这样）";
      ValidateMachineMatch.Foreground = new System.Windows.Media.SolidColorBrush(
          (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00b894"));

      ValidateExpiry.Text = expiryDisplay;
      ValidateType.Text = LicenseInfo.TypeToCode(licenseType) switch
      {
        "T" => "\U0001f550 试用（5分钟）",
        "1" => "\U0001f4c5 1年期",
        "2" => "\U0001f5d3\ufe0f 2年期",
        "P" => "\u267e\ufe0f 永久授权",
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
        StatusTextBlock.Text = "\u26a0\ufe0f 请先生成授权码";
        return;
      }

      try
      {
        string machineId = TargetMachineIdTextBox.Text.Trim().ToUpperInvariant();
        string prefix = ComputeMachineHash(machineId);

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
          MachineId = machineId,
          MachineIdPrefix = prefix,
          LicenseType = licenseType,
          IssuedTime = issueTime,
          ExpiryTime = GetExpiryTime(licenseType, issueTime),
          IssuedBy = IssuerTextBox.Text.Trim(),
          Note = NoteTextBox.Text.Trim()
        };

        _store.AddRecord(record);
        RefreshHistory();
        StatusTextBlock.Text = $"\u2705 记录已保存 | 共 {_records.Count} 条历史记录";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"\u26a0\ufe0f 保存失败: {ex.Message}";
      }
    }

    private void ClearResultButton_Click(object sender, RoutedEventArgs e)
    {
      GeneratedCodeTextBox.Text = "";
      ValidateHmac.Text = "\u2014";
      ValidateMachineMatch.Text = "\u2014";
      ValidateExpiry.Text = "\u2014";
      ValidateType.Text = "\u2014";
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
        StatusTextBlock.Text = "\u26a0\ufe0f 没有可复制的授权码";
        return;
      }
      try
      {
        Clipboard.SetText(code);
        StatusTextBlock.Text = $"\u2705 授权码已复制到剪贴板";
      }
      catch (Exception ex)
      {
        StatusTextBlock.Text = $"\u26a0\ufe0f 复制失败: {ex.Message}";
      }
    }

    private void CopyHistoryCode_Click(object sender, RoutedEventArgs e)
    {
      if (sender is Button btn && btn.Tag is LicenseIssuanceRecord record)
      {
        try
        {
          Clipboard.SetText(record.LicenseCode);
          StatusTextBlock.Text = $"\u2705 已复制: {record.LicenseCode}";
        }
        catch (Exception ex)
        {
          StatusTextBlock.Text = $"\u26a0\ufe0f 复制失败: {ex.Message}";
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
          StatusTextBlock.Text = $"\u2705 记录已删除";
        }
      }
    }

    private void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
      RefreshHistory();
      StatusTextBlock.Text = $"\u2705 已刷新 | 共 {_records.Count} 条记录";
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
        StatusTextBlock.Text = "\u2705 历史记录已清空";
      }
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
      if (_records.Count == 0)
      {
        StatusTextBlock.Text = "\u26a0\ufe0f 没有可导出的记录";
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
          StatusTextBlock.Text = $"\u2705 已导出到: {dialog.FileName}";
        }
        catch (Exception ex)
        {
          StatusTextBlock.Text = $"\u26a0\ufe0f 导出失败: {ex.Message}";
        }
      }
    }

    private void RefreshHistory()
    {
      _records = _store.GetAllRecords();
      // 按发行时间倒序展示（最新在前），序号从 1 连续编号
      var ordered = _records.OrderByDescending(r => r.IssuedTime).ThenByDescending(r => r.CreatedAt).ToList();
      for (int i = 0; i < ordered.Count; i++)
      {
        ordered[i].SequenceNumber = i + 1;
      }
      _records = ordered;

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