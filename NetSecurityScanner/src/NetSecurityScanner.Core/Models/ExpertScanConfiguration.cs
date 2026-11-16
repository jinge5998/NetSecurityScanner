using System;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 专家模式扫描配置。
    ///
    /// 原先定义在 NetSecurityScanner.Desktop 的 ExpertModeWindow.xaml.cs 内部（第 7729 行），
    /// 导致 Core.Tests 无法引用它，专家模式 7834 行代码因此长期处于零测试覆盖状态。
    /// 迁移至 Core 层后，配置模型与纯逻辑（ExpertScanPlanner）均可被独立测试。
    ///
    /// 序列化兼容性：本类通过 System.Text.Json 读写（见 ExpertModeWindow 的预设加载/保存），
    /// 不带类型名信息，因此跨命名空间迁移不影响既有预设 JSON 文件的读取。
    /// </summary>
    public class ExpertScanConfiguration
    {
        public DateTime StartTime { get; set; } = DateTime.Now;
        public string TargetType { get; set; } = "Single";
        public string TargetValue { get; set; } = "";
        public bool ReverseDns { get; set; } = false;
        public bool HostDiscovery { get; set; } = true;
        public string ExcludeHosts { get; set; } = "";

        public string PortMode { get; set; } = "Common";
        public string CustomPorts { get; set; } = "";
        public bool TcpScan { get; set; } = true;
        public bool UdpScan { get; set; } = false;
        public bool SynScan { get; set; } = false;
        public bool ServiceDetection { get; set; } = true;
        public bool OsDetection { get; set; } = false;
        public bool ScriptScan { get; set; } = false;

        /// <summary>
        /// 自定义 NSE 脚本参数。
        /// 注意：对应输入控件 NseScriptArgsTextBox 已从界面移除，CollectConfig 恒将其置为 ""，
        /// 仅为兼容旧配置文件而保留本字段。因此 GenerateNmapCommand 中依赖它的分支目前不可达。
        /// </summary>
        public string NseScriptArgs { get; set; } = "";

        public int ServiceIntensity { get; set; } = 1;
        public string ExcludePorts { get; set; } = "";

        public int TcpConcurrency { get; set; } = 50;
        public int UdpConcurrency { get; set; } = 20;
        public int TcpTimeout { get; set; } = 500;
        public int UdpTimeout { get; set; } = 1000;
        public int RetryCount { get; set; } = 1;

        /// <summary>
        /// 服务识别超时（ms）。
        /// 已知缺陷：界面提供滑块可调节，但没有任何扫描逻辑或 Nmap 命令生成读取该值，
        /// ScanProfileConfig 中亦无对应字段可承载，属于纯装饰性配置。
        /// </summary>
        public int ServiceDetectTimeout { get; set; } = 2000;

        public bool RateLimit { get; set; } = false;
        public int PacketRate { get; set; } = 1000;
        public bool Randomize { get; set; } = false;
        public bool StealthMode { get; set; } = false;
        public bool RandomPortOrder { get; set; } = false;
        public bool RandomTargetOrder { get; set; } = false;

        public string SourcePort { get; set; } = "";
        public string Mtu { get; set; } = "1500";
        public bool FragmentPackets { get; set; } = false;
        public bool BadChecksum { get; set; } = false;
        public bool DecoyScan { get; set; } = false;
        public string DecoyIps { get; set; } = "";
        public bool IdleScan { get; set; } = false;
        public string ZombieHost { get; set; } = "";
        public bool SourceRouting { get; set; } = false;
        public int Verbosity { get; set; } = 1;
        public bool SaveOutput { get; set; } = true;
        public string OutputDir { get; set; } = "";
        public bool OutputJson { get; set; } = true;
        public bool OutputHtml { get; set; } = false;
        public bool OutputCsv { get; set; } = false;
        public bool ShowOpenOnly { get; set; } = false;
        public bool PingProbe { get; set; } = true;
        public int SourcePortMin { get; set; } = 0;
        public int SourcePortMax { get; set; } = 0;
    }
}
