using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  public class LicenseIssuerStore
  {
    private readonly string _storeFilePath;
    private static readonly string _dataDir;

    static LicenseIssuerStore()
    {
      _dataDir = Path.Combine(
          Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
          "NetSecurityScanner", "licenseIssuer");
    }

    public LicenseIssuerStore()
    {
      if (!Directory.Exists(_dataDir))
        Directory.CreateDirectory(_dataDir);
      _storeFilePath = Path.Combine(_dataDir, "issuance_records.json");
    }

    public List<LicenseIssuanceRecord> GetAllRecords()
    {
      try
      {
        if (!File.Exists(_storeFilePath))
          return new List<LicenseIssuanceRecord>();

        var json = File.ReadAllText(_storeFilePath);
        if (string.IsNullOrWhiteSpace(json))
          return new List<LicenseIssuanceRecord>();

        var store = JsonSerializer.Deserialize<LicenseIssuanceData>(json);
        return store?.Records ?? new List<LicenseIssuanceRecord>();
      }
      catch
      {
        return new List<LicenseIssuanceRecord>();
      }
    }

    public void AddRecord(LicenseIssuanceRecord record)
    {
      var records = GetAllRecords();
      records.Insert(0, record);

      if (records.Count > 5000)
        records = records.Take(5000).ToList();

      SaveRecords(records);
    }

    public void RemoveRecord(string id)
    {
      var records = GetAllRecords();
      records.RemoveAll(r => r.Id == id);
      SaveRecords(records);
    }

    public void ClearAllRecords()
    {
      SaveRecords(new List<LicenseIssuanceRecord>());
    }

    public string ExportRecordsToCsv(IEnumerable<LicenseIssuanceRecord> records)
    {
      var sb = new System.Text.StringBuilder();
      sb.AppendLine("ID,机器码前缀,授权类型,发行时间,到期时间,发行者,备注,授权码");
      foreach (var r in records)
      {
        var note = r.Note.Replace("\"", "\"\"");
        var code = r.LicenseCode.Replace("\"", "\"\"");
        sb.AppendLine($"{r.Id},{r.MachineIdPrefix},{r.LicenseTypeName},{r.IssuedTime:yyyy-MM-dd HH:mm},{r.ExpiryDisplay},{r.IssuedBy},\"{note}\",\"{code}\"");
      }
      return sb.ToString();
    }

    private void SaveRecords(List<LicenseIssuanceRecord> records)
    {
      try
      {
        var store = new LicenseIssuanceData { Records = records };
        var json = JsonSerializer.Serialize(store, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_storeFilePath, json);
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"保存授权记录失败: {ex.Message}");
      }
    }
  }
}