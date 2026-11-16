using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSecurityScanner.Data;
using NetSecurityScanner.Models;
using NetSecurityScanner.Core;
using NetSecurityScanner.Services;
using NetSecurityScanner.Detection;

namespace NetSecurityScanner.Core
{
    /// <summary>
    /// 工作流管理器 - 协调整个扫描工作流程
    /// 管理端口扫描、漏洞扫描、数据存储和状态管理
    /// </summary>
    public class WorkflowManager
    {
        private readonly JSONDatabaseService _databaseService;
        private readonly PortScannerService _portScannerService;
        private readonly VulnerabilityDetectionService _vulnerabilityDetectionService;
        private readonly RiskAssessmentService _riskAssessmentService;
        private readonly ReportGeneratorService _reportGeneratorService;
        private readonly ScanResultCache _scanResultCache;
        private readonly Logger _logger;
        
        // 取消令牌源
        private CancellationTokenSource? _cancellationTokenSource;
        
        // 工作流状态
        public enum WorkflowStatus
        {
            Idle,
            Initializing,
            PortScanning,
            VulnerabilityScanning,
            RiskAssessing,
            ReportGenerating,
            Completed,
            Failed,
            Cancelled
        }
        
        // 当前状态
        public WorkflowStatus CurrentStatus { get; private set; }
        
        // 进度信息
        public double Progress { get; private set; }
        public string CurrentTask { get; private set; }
        
        // 错误信息
        public string ErrorMessage { get; private set; }
        
        // 扫描配置
        public ScanConfiguration Configuration { get; set; }
        
        public WorkflowManager()
        {
            // 初始化依赖服务
            _databaseService = new JSONDatabaseService();
            _portScannerService = new PortScannerService();
            _vulnerabilityDetectionService = new VulnerabilityDetectionService();
            _riskAssessmentService = new RiskAssessmentService();
            _reportGeneratorService = new ReportGeneratorService();
            _scanResultCache = new ScanResultCache();
            _logger = new Logger();
            
            // 初始化状态
            CurrentStatus = WorkflowStatus.Idle;
            Progress = 0;
            CurrentTask = "准备就绪";
            ErrorMessage = string.Empty;
            
            // 初始化默认配置 - 200线程高并发扫描
            Configuration = new ScanConfiguration
            {
                TargetHosts = "127.0.0.1",
                PortRange = "1-1024",
                ScanType = "全面扫描",
                ThreadCount = 200, // 200线程并发扫描，提高速度
                Timeout = 2000,    // 减少超时时间，加快扫描
                RetryCount = 1     // 减少重试次数，加快扫描
            };
        }
        
        /// <summary>
        /// 启动扫描工作流
        /// </summary>
        public async Task StartWorkflowAsync(ScanTask task, IProgress<WorkflowProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            // 创建取消令牌源，链接外部取消令牌
            _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var linkedToken = _cancellationTokenSource.Token;
            
            try
            {
                // 初始化工作流
                InitializeWorkflow(task);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
                
                // 1. 端口扫描
                linkedToken.ThrowIfCancellationRequested();
                await ExecutePortScanAsync(task, linkedToken);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
                
                // 2. 漏洞扫描
                linkedToken.ThrowIfCancellationRequested();
                await ExecuteVulnerabilityScanAsync(task, linkedToken);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
                
                // 3. 风险评估
                linkedToken.ThrowIfCancellationRequested();
                await ExecuteRiskAssessmentAsync(task, linkedToken);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
                
                // 4. 报告生成
                linkedToken.ThrowIfCancellationRequested();
                await GenerateReportAsync(task, linkedToken);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
                
                // 完成工作流
                CompleteWorkflow(task);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask });
            }
            catch (OperationCanceledException)
            {
                // 用户取消扫描，这是正常操作，不作为错误处理
                _logger.Info($"工作流被取消: {task.TaskName}");
                task.Status = "已取消";
                task.EndTime = DateTime.Now;
                CurrentStatus = WorkflowStatus.Cancelled;
                CurrentTask = "扫描已取消";
                ErrorMessage = string.Empty;
                
                // 报告取消状态
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask, IsCancelled = true });
                
                // 更新数据库中的任务状态
                try
                {
                    _databaseService.UpdateScanTask(task);
                }
                catch (Exception dbEx)
                {
                    _logger.Error($"更新任务状态失败: {dbEx.Message}");
                }
            }
            catch (Exception ex)
            {
                // 处理工作流失败
                _logger.Error($"工作流执行失败: {ex.Message}");
                FailWorkflow(ex.Message);
                progress?.Report(new WorkflowProgressInfo { Status = CurrentStatus.ToString(), Progress = Progress, Message = CurrentTask, ErrorMessage = ErrorMessage });
                throw;
            }
            finally
            {
                // 清理取消令牌源
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
            }
        }
        
        /// <summary>
        /// 初始化工作流
        /// </summary>
        private void InitializeWorkflow(ScanTask task)
        {
            try
            {
                _logger.Info($"初始化工作流: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.Initializing;
                Progress = 0;
                CurrentTask = "初始化工作流";
                ErrorMessage = string.Empty;
                
                // 设置任务状态
                task.Status = "进行中";
                task.StartTime = DateTime.Now;
                
                // 保存任务到JSON数据库
                _databaseService.AddScanTask(task);
                
                _logger.Info($"工作流初始化完成: {task.TaskName}");
            }
            catch (Exception ex)
            {
                throw new Exception($"初始化工作流失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 执行端口扫描
        /// </summary>
        private async Task ExecutePortScanAsync(ScanTask task, CancellationToken cancellationToken)
        {
            try
            {
                _logger.Info($"开始端口扫描: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.PortScanning;
                Progress = 25;
                CurrentTask = "执行端口扫描";
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 解析目标主机
                var targets = task.TargetHosts.Split(',')
                    .Select(t => t.Trim())
                    .Where(t => !string.IsNullOrEmpty(t))
                    .ToList();
                
                if (!targets.Any())
                {
                    throw new Exception("未指定目标主机");
                }
                
                // 执行端口扫描
                var scanResults = new List<ScanResult>();
                
                foreach (var target in targets)
                {
                    // 检查取消请求
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    _logger.Info($"扫描目标: {target}");
                    
                    // 解析端口范围
                    var portRange = Configuration.PortRange.Split('-');
                    int startPort = int.Parse(portRange[0]);
                    int endPort = portRange.Length > 1 ? int.Parse(portRange[1]) : startPort;
                    
                    // 生成端口列表
                    var ports = new List<int>();
                    for (int i = startPort; i <= endPort; i++)
                    {
                        ports.Add(i);
                    }
                    
                    // 配置扫描选项
                    var scanOptions = new ScanOptions
                    {
                        Timeout = Configuration.Timeout,
                        MaxConcurrency = Configuration.ThreadCount,
                        RetryCount = Configuration.RetryCount
                    };
                    
                    // 执行扫描
                    var results = await _portScannerService.ScanPortsAsync(
                        target,
                        ports,
                        scanOptions,
                        null,
                        cancellationToken
                    );
                    
                    // 检查取消请求
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    // 转换为ScanResult
                    foreach (var portInfo in results)
                    {
                        scanResults.Add(new ScanResult
                        {
                            Host = portInfo.Host,
                            Port = portInfo.PortNumber,
                            Service = portInfo.Service,
                            IsVulnerable = false,
                            ScanTime = DateTime.Now
                        });
                    }
                }
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 保存扫描结果到JSON数据库
                _logger.Info($"端口扫描完成，发现 {scanResults.Count} 个结果");
                await _databaseService.AddScanTaskWithResultsAsync(task, scanResults);
                
                // 缓存扫描结果
                foreach (var result in scanResults)
                {
                    var portInfo = new PortInfo
                    {
                        Host = result.Host,
                        PortNumber = result.Port,
                        Status = result.IsVulnerable ? "开放" : "关闭",
                        Service = result.Service,
                        Version = result.Service,
                        Protocol = "TCP",
                        ServiceDetails = result.Service,
                        ScanTime = DateTime.Now
                    };
                    _scanResultCache.AddToCache(result.Host, result.Port, "TCP", portInfo);
                }
                
            }
            catch (OperationCanceledException)
            {
                _logger.Info($"端口扫描被取消: {task.TaskName}");
                throw;
            }
            catch (Exception ex)
            {
                throw new Exception($"端口扫描失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 执行漏洞扫描
        /// </summary>
        private async Task ExecuteVulnerabilityScanAsync(ScanTask task, CancellationToken cancellationToken)
        {
            try
            {
                _logger.Info($"开始漏洞扫描: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.VulnerabilityScanning;
                Progress = 50;
                CurrentTask = "执行漏洞扫描";
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 从JSON数据库获取开放端口结果
                var openPorts = _databaseService.GetOpenPortResults(task.TaskId);
                
                if (!openPorts.Any())
                {
                    _logger.Info("未发现开放端口，跳过漏洞扫描");
                    return;
                }
                
                _logger.Info($"发现 {openPorts.Count} 个开放端口，开始漏洞扫描");
                
                // 执行漏洞扫描
                var vulnerabilityResults = new List<ScanResult>();
                
                // 创建目标信息
                var targetInfo = new TargetInfo
                {
                    Host = task.TargetHosts,
                    Services = openPorts.Select(p => new ServiceInfo
                    {
                        Port = p.Port,
                        Name = p.Service,
                        Version = p.Service
                    }).ToList()
                };
                
                var vulnOptions = new VulnScanOptions
                {
                    EnablePocVerification = true,
                    EnableCveMatching = true
                };
                
                // 执行漏洞检测
                var vulnerabilities = await _vulnerabilityDetectionService.DetectVulnerabilitiesAsync(
                    targetInfo,
                    vulnOptions,
                    null,
                    cancellationToken
                );
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 处理漏洞结果
                foreach (var vulnerability in vulnerabilities)
                {
                    vulnerability.TaskId = task.TaskId;
                    // 保存漏洞信息
                    _databaseService.AddVulnerability(vulnerability);
                    
                    // 创建漏洞扫描结果
                    var result = new ScanResult
                    {
                        TaskId = task.TaskId,
                        Host = task.TargetHosts,
                        Port = 0, // 可以从漏洞信息中获取
                        Service = vulnerability.Name,
                        IsVulnerable = true,
                        VulnerabilityId = vulnerability.VulnerabilityId,
                        ScanTime = DateTime.Now
                    };
                    
                    vulnerabilityResults.Add(result);
                }
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 保存漏洞扫描结果到JSON数据库
                if (vulnerabilityResults.Any())
                {
                    _logger.Info($"漏洞扫描完成，发现 {vulnerabilityResults.Count} 个漏洞");
                    await _databaseService.AddScanResultsAsync(vulnerabilityResults);
                }
                else
                {
                    _logger.Info("漏洞扫描完成，未发现漏洞");
                }
                
            }
            catch (OperationCanceledException)
            {
                _logger.Info($"漏洞扫描被取消: {task.TaskName}");
                throw;
            }
            catch (Exception ex)
            {
                throw new Exception($"漏洞扫描失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 执行风险评估
        /// </summary>
        private async Task ExecuteRiskAssessmentAsync(ScanTask task, CancellationToken cancellationToken)
        {
            try
            {
                _logger.Info($"开始风险评估: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.RiskAssessing;
                Progress = 75;
                CurrentTask = "执行风险评估";
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 从JSON数据库获取扫描结果
                var scanResults = _databaseService.GetScanResultsByTaskId(task.TaskId);
                
                if (!scanResults.Any())
                {
                    _logger.Info("无扫描结果，跳过风险评估");
                    return;
                }
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 执行风险评估
                var riskAssessment = _riskAssessmentService.AssessRiskExpert(new List<VulnerabilityResult>());
                var riskScore = riskAssessment.TotalRiskScore;

                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();

                // 保存风险评估结果（这里可以扩展保存到专门的风险评估表）
                _logger.Info($"风险评估完成，风险评分: {riskScore}");
                
            }
            catch (OperationCanceledException)
            {
                _logger.Info($"风险评估被取消: {task.TaskName}");
                throw;
            }
            catch (Exception ex)
            {
                throw new Exception($"风险评估失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 生成报告
        /// </summary>
        private async Task GenerateReportAsync(ScanTask task, CancellationToken cancellationToken)
        {
            try
            {
                _logger.Info($"开始生成报告: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.ReportGenerating;
                Progress = 90;
                CurrentTask = "生成报告";
                
                // 检查取消请求
                cancellationToken.ThrowIfCancellationRequested();
                
                // 生成报告
                var reportPath = await _reportGeneratorService.GenerateReportAsync(
                    task.TaskId,
                    "Technical",
                    "Html"
                );
                
                _logger.Info($"报告生成完成: {reportPath}");
                
            }
            catch (OperationCanceledException)
            {
                _logger.Info($"报告生成被取消: {task.TaskName}");
                throw;
            }
            catch (Exception ex)
            {
                throw new Exception($"生成报告失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 完成工作流
        /// </summary>
        private void CompleteWorkflow(ScanTask task)
        {
            try
            {
                _logger.Info($"工作流完成: {task.TaskName}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.Completed;
                Progress = 100;
                CurrentTask = "工作流完成";
                
                // 更新任务状态
                task.Status = "完成";
                task.EndTime = DateTime.Now;
                
                // 保存任务更新到JSON数据库
                _databaseService.UpdateScanTask(task);
                
                _logger.Info($"工作流成功完成: {task.TaskName}");
            } catch (Exception ex)
            {
                _logger.Error($"完成工作流失败: {ex.Message}");
                // 不抛出异常，因为工作流主要任务已完成
            }
        }
        
        /// <summary>
        /// 工作流失败
        /// </summary>
        private void FailWorkflow(string errorMessage)
        {
            try
            {
                _logger.Error($"工作流失败: {errorMessage}");
                
                // 更新状态
                CurrentStatus = WorkflowStatus.Failed;
                Progress = 0;
                CurrentTask = "工作流失败";
                ErrorMessage = errorMessage;
                
            } catch (Exception ex)
            {
                _logger.Error($"处理工作流失败时出错: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 取消工作流
        /// </summary>
        public void CancelWorkflow()
        {
            try
            {
                _logger.Info("取消工作流");
                
                // 取消正在执行的任务
                if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
                {
                    _cancellationTokenSource.Cancel();
                    _logger.Info("已发送取消请求");
                }
                
                // 同时取消各个服务的扫描
                _portScannerService.CancelScan();
                _vulnerabilityDetectionService.CancelScan();
                
                // 更新状态
                CurrentStatus = WorkflowStatus.Cancelled;
                CurrentTask = "工作流已取消";
                
            }
            catch (Exception ex)
            {
                _logger.Error($"取消工作流失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 检查工作流是否已取消
        /// </summary>
        public bool IsCancellationRequested => _cancellationTokenSource?.IsCancellationRequested ?? false;
        
        /// <summary>
        /// 获取工作流状态信息
        /// </summary>
        public WorkflowStatusInfo GetStatusInfo()
        {
            return new WorkflowStatusInfo
            {
                Status = CurrentStatus.ToString(),
                Progress = Progress,
                CurrentTask = CurrentTask,
                ErrorMessage = ErrorMessage,
                Timestamp = DateTime.Now
            };
        }
        
        /// <summary>
        /// 获取扫描历史
        /// </summary>
        public List<ScanTask> GetScanHistory()
        {
            try
            {
                return _databaseService.GetAllScanTasks();
            } catch (Exception ex)
            {
                _logger.Error($"获取扫描历史失败: {ex.Message}");
                return new List<ScanTask>();
            }
        }
        
        /// <summary>
        /// 获取扫描结果
        /// </summary>
        public List<ScanResult> GetScanResults(int taskId)
        {
            try
            {
                return _databaseService.GetScanResultsByTaskId(taskId);
            } catch (Exception ex)
            {
                _logger.Error($"获取扫描结果失败: {ex.Message}");
                return new List<ScanResult>();
            }
        }
        
        /// <summary>
        /// 清理过期数据
        /// </summary>
        public void CleanupOldData(int daysToKeep = 30)
        {
            try
            {
                _logger.Info($"清理过期数据，保留 {daysToKeep} 天");
                _databaseService.CleanupOldData(daysToKeep);
                _logger.Info("清理过期数据完成");
            } catch (Exception ex)
            {
                _logger.Error($"清理过期数据失败: {ex.Message}");
            }
        }
    }
    
    /// <summary>
    /// 工作流状态信息
    /// </summary>
    public class WorkflowStatusInfo
    {
        public string Status { get; set; } = string.Empty;
        public double Progress { get; set; }
        public string CurrentTask { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
    
    /// <summary>
    /// 工作流进度信息 - 用于进度报告
    /// </summary>
    public class WorkflowProgressInfo
    {
        public string Status { get; set; } = string.Empty;
        public double Progress { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public bool IsCancelled { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }
    
    /// <summary>
    /// 扫描配置
    /// </summary>
    public class ScanConfiguration
    {
        public string TargetHosts { get; set; } = "127.0.0.1";
        public string PortRange { get; set; } = "1-1024";
        public string ScanType { get; set; } = "全面扫描";
        public int ThreadCount { get; set; } = 200; // 200线程并发扫描
        public int Timeout { get; set; } = 2000;    // 2秒超时
        public int RetryCount { get; set; } = 1;    // 1次重试
    }
    
    /// <summary>
    /// 端口扫描配置
    /// </summary>
    public class PortScanConfig
    {
        public string Target { get; set; }
        public string PortRange { get; set; }
        public int ThreadCount { get; set; }
        public int Timeout { get; set; }
        public int RetryCount { get; set; }
    }
}