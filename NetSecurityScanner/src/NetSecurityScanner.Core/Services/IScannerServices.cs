using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
  /// <summary>
  /// 端口扫描器接口
  /// </summary>
  public interface IPortScanner
  {
    /// <summary>TCP 端口扫描</summary>
    Task<List<PortScanResult>> ScanTcpPortsAsync(
        string targetIp,
        List<int> ports,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default,
        ScanPolicy? scanPolicy = null);

    /// <summary>UDP 端口扫描</summary>
    Task<List<PortScanResult>> ScanUdpPortsAsync(
        string targetIp,
        List<int> ports,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default,
        ScanPolicy? scanPolicy = null);
  }

  /// <summary>
  /// 漏洞扫描器接口
  /// </summary>
  public interface IVulnerabilityScanner
  {
    /// <summary>执行漏洞扫描</summary>
    Task<List<VulnerabilityResult>> ScanAsync(
        string targetIp,
        List<PortInfo> openPorts,
        string scanPolicy,
        IProgress<(string message, int percentage)> progress,
        CancellationToken cancellationToken);
  }

  /// <summary>
  /// 插件编排器接口
  /// </summary>
  public interface IPluginOrchestrator
  {
    /// <summary>对目标执行插件扫描</summary>
    Task<List<VulnerabilityResult>> ScanTargetAsync(
        string targetIp,
        List<int> ports,
        IEnumerable<string>? selectedPluginIds = null,
        CancellationToken ct = default,
        string? traceId = null);
  }

  /// <summary>
  /// JSON 数据库服务接口
  /// </summary>
  public interface IJsonDatabaseService
  {
    /// <summary>保存扫描历史</summary>
    Task<bool> SaveScanHistoryAsync(ScanHistoryItem item);

    /// <summary>保存扫描结果</summary>
    Task<bool> SaveScanResultAsync(CompleteScanResult scanResult);

    /// <summary>更新扫描历史</summary>
    Task<bool> UpdateScanHistoryAsync(string scanId, ScanHistoryItem updatedItem);
  }
}