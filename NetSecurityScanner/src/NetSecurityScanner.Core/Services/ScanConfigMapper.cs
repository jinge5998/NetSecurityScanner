using System;
using NetSecurityScanner.Core.Models;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 专家模式配置 → 扫描引擎参数的映射。
    ///
    /// 这段映射原先内联在 ExpertModeWindow.ExecuteRustScanAsync 中，无法脱离 WPF 测试。
    /// 抽取后，「界面配置究竟有哪些字段能真正下发到扫描引擎」成为一个可断言的契约
    /// （见 ExpertScanConfigEffectivenessContractTests）。
    ///
    /// ⚠️ 关键事实：<see cref="ScanProfileConfig"/> 只有 9 个字段，
    /// 而 <see cref="ExpertScanConfiguration"/> 有 40 余个。
    /// 二者的差集就是「界面可配置、但对真实扫描无任何影响」的那批选项——
    /// 包括 SYN 半开、操作系统识别、服务检测强度、MTU、分片、诱饵、僵尸扫描、源路由等。
    /// 这类选项只会被 NmapCommandBuilder 翻译成命令字符串供用户复制到终端执行，
    /// 程序自身的 Rust / C# 引擎并不消费它们。
    /// </summary>
    public static class ScanConfigMapper
    {
        /// <summary>
        /// 把专家模式配置转换为下发给扫描引擎（Rust / C#）的参数。
        /// </summary>
        /// <param name="config">专家模式界面配置。</param>
        public static ScanProfileConfig ToScanProfileConfig(ExpertScanConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            return new ScanProfileConfig
            {
                TcpConcurrency = config.TcpConcurrency,
                UdpConcurrency = config.UdpConcurrency,
                TimeoutMs = config.TcpTimeout,

                // UDP 超时单独下发，避免 Rust 端复用 TCP 超时导致 UDP 结果失真。
                // 0 表示「未设置」，交由调用方的 udpTimeoutMs 参数兜底（见 ScanProfileConfig.Normalize）。
                UdpTimeoutMs = config.UdpTimeout > 0 ? config.UdpTimeout : 0,

                RetryCount = config.RetryCount,
                EnableServiceDetection = config.ServiceDetection,

                // 两个开关必须同时为真才做存活探测：
                // PingProbe 是性能调优页的「扫描前 Ping 探测」，
                // HostDiscovery 是目标配置页的「先进行主机发现」。
                EnablePingProbe = config.PingProbe && config.HostDiscovery
            };
        }

        /// <summary>
        /// 计算 Rust 引擎的协议参数。
        ///
        /// Rust 端约定取值为 tcp / udp / both（见 scanner.rs 的 ScanConfig.protocol 注释）。
        /// 此前传 "tcp,udp" 会被 Rust 走 else 分支按 both 处理，但并不会命中
        /// proto == "both" 的 UDP 并发名额分配逻辑，导致 UDP 并发控制失效、UDP 扫描大量超时。
        /// 因此 TCP+UDP 同时勾选时必须传 "both"。
        /// </summary>
        /// <param name="config">专家模式界面配置。</param>
        public static string ResolveProtocol(ExpertScanConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));

            if (config.TcpScan && config.UdpScan) return "both";
            return config.UdpScan ? "udp" : "tcp";
        }

        /// <summary>
        /// 计算启动 Rust 服务时使用的 TCP 并发数。
        /// 非正数视为未设置，回退到 1000（与 ExecuteRustScanAsync 原有兜底一致）。
        /// </summary>
        public static int ResolveServiceConcurrency(ExpertScanConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            return config.TcpConcurrency > 0 ? config.TcpConcurrency : 1000;
        }

        /// <summary>
        /// 计算启动 Rust 服务时使用的 TCP 超时（ms）。
        /// 非正数视为未设置，回退到 200ms。
        /// </summary>
        public static int ResolveServiceTcpTimeout(ExpertScanConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            return config.TcpTimeout > 0 ? config.TcpTimeout : 200;
        }

        /// <summary>
        /// 计算启动 Rust 服务时使用的 UDP 超时（ms）。
        /// 非正数视为未设置，回退到 500ms。
        /// </summary>
        public static int ResolveServiceUdpTimeout(ExpertScanConfiguration config)
        {
            if (config == null) throw new ArgumentNullException(nameof(config));
            return config.UdpTimeout > 0 ? config.UdpTimeout : 500;
        }
    }
}
