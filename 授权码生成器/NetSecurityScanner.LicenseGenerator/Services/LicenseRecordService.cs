using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using NetSecurityScanner.LicenseGenerator.Models;

namespace NetSecurityScanner.LicenseGenerator.Services
{
    public class LicenseRecordService
    {
        private readonly string _databasePath;
        private List<LicenseRecord> _records;

        public LicenseRecordService()
        {
            _databasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "license_records.json");
            _records = LoadFromFile();
        }

        public void AddRecord(LicenseRecord record)
        {
            _records.Insert(0, record);
            SaveToFile();
        }

        public void AddRecords(List<LicenseRecord> records)
        {
            _records.InsertRange(0, records);
            SaveToFile();
        }

        public List<LicenseRecord> GetAllRecords()
        {
            return _records.ToList();
        }

        public List<LicenseRecord> SearchByMachineId(string machineId)
        {
            if (string.IsNullOrWhiteSpace(machineId))
                return _records.ToList();

            return _records.Where(r => r.MachineId.IndexOf(machineId, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
        }

        public List<LicenseRecord> SearchByTimeRange(DateTime? startTime, DateTime? endTime)
        {
            var query = _records.AsEnumerable();

            if (startTime.HasValue)
                query = query.Where(r => r.IssuedTime >= startTime.Value);

            if (endTime.HasValue)
                query = query.Where(r => r.IssuedTime <= endTime.Value);

            return query.ToList();
        }

        public bool DeleteRecord(string recordId)
        {
            var record = _records.FirstOrDefault(r => r.RecordId == recordId);
            if (record != null)
            {
                _records.Remove(record);
                SaveToFile();
                return true;
            }
            return false;
        }

        private void SaveToFile()
        {
            try
            {
                string json = JsonConvert.SerializeObject(_records, Formatting.Indented);
                File.WriteAllText(_databasePath, json);
            }
            catch
            {
            }
        }

        private List<LicenseRecord> LoadFromFile()
        {
            try
            {
                if (!File.Exists(_databasePath))
                    return new List<LicenseRecord>();

                string json = File.ReadAllText(_databasePath);
                return JsonConvert.DeserializeObject<List<LicenseRecord>>(json) ?? new List<LicenseRecord>();
            }
            catch
            {
                return new List<LicenseRecord>();
            }
        }
    }
}
