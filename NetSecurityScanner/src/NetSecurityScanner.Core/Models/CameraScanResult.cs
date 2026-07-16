using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class CameraScanResult
  {
    public string Ip { get; set; } = string.Empty;
    public string IpType { get; set; } = "IPv4";
    public string Mac { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string FirmwareVersion { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public bool IsOnline { get; set; }
    public List<CameraPortInfo> OpenPorts { get; set; } = new();
    public List<CameraVulnerability> Vulnerabilities { get; set; } = new();
    public List<CameraWeakPassword> WeakPasswords { get; set; } = new();
    public CameraRiskAssessment RiskAssessment { get; set; } = new();
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public int ResponseTimeMs { get; set; }
    public bool HasTelnet { get; set; }
    public string Preset { get; set; } = "标准扫描";
    public string ScanEngine { get; set; } = "本地";
    public List<string> TopVulnerabilities { get; set; } = new();

    // v2 增强字段
    public string SessionId { get; set; } = string.Empty;
    public string ScheduledTaskId { get; set; } = string.Empty;
    public string TemplateId { get; set; } = string.Empty;
    public string MonitoringMode { get; set; } = "单次"; // 单次/持续监控/定时任务
    public DateTime? LastCheckedTime { get; set; }
    public string AlertLevel { get; set; } = "无"; // 无/低/中/高/严重

    // v5 精准判定字段
    public string VerificationMethod { get; set; } = "";   // 端口启发/HTTP指纹/RTSP响应/ONVIF协议/反例黑名单/未识别
    public double VerificationConfidence { get; set; }       // 0-1
    public string VerificationEvidence { get; set; } = "";   // 命中证据
  }
}