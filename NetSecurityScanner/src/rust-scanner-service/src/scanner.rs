//! 高性能端口扫描模块
//!
//! TCP 端口发现由 RustScan 引擎（`vendor/RustScan-2.4.1`）承担，
//! UDP 扫描、TCP Banner 抓取、Ping 存活探测与实时进度上报由本模块实现。
//! 对外接口（`scan_batch` / `ScanConfig` / `PortScanResult` / `ScanProgress`）保持不变。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::rustscan_engine::RustScanEngine;

/// 端口扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    /// 目标 IP
    pub target_ip: String,
    /// 端口号
    pub port: u16,
    /// 协议类型 (TCP/UDP)
    pub protocol: String,
    /// 状态 (开放/关闭/过滤)
    pub status: String,
    /// 服务名称
    pub service: String,
    /// 服务版本
    pub version: String,
    /// Banner 信息
    pub banner: String,
    /// 扫描耗时(ms)
    pub scan_time_ms: u64,
}

/// 扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// 目标 IP 列表
    pub targets: Vec<String>,
    /// 端口列表
    pub ports: Vec<u16>,
    /// 扫描协议 (tcp, udp, both)
    pub protocol: String,
    /// 最大并发数
    pub concurrency: usize,
    /// TCP 超时(ms)
    pub tcp_timeout_ms: u64,
    /// UDP 超时(ms)
    pub udp_timeout_ms: u64,
    /// 是否检测服务版本
    pub detect_service: bool,
    /// 是否包含关闭端口
    pub include_closed: bool,
    /// TCP 并发数（覆盖扫描器默认值）
    pub tcp_concurrency: Option<u32>,
    /// UDP 并发数（覆盖扫描器默认值）
    pub udp_concurrency: Option<u32>,
    /// 开放端口重试确认次数
    pub retry_count: Option<u32>,
    /// 扫描前是否执行 Ping 存活探测
    pub enable_ping_probe: Option<bool>,
}

/// 扫描进度报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// 当前扫描目标索引
    pub current_target_index: usize,
    /// 总目标数
    pub total_targets: usize,
    /// 当前目标 IP
    pub current_target: String,
    /// 已扫描端口数
    pub scanned_ports: usize,
    /// 总端口数
    pub total_ports: usize,
    /// 发现的开放端口数
    pub open_ports_found: usize,
    /// 扫描进度百分比
    pub progress_percent: f64,
    /// 当前扫描速度(端口/秒)
    pub scan_rate: f64,
    /// 预计剩余时间(秒)
    pub estimated_remaining_seconds: u64,
}

/// 高频开放端口列表，扫描时优先处理这些端口，以便更快发现开放端口
const HIGH_FREQUENCY_PORTS: [u16; 31] = [
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3306, 3389, 5432, 6379, 27017, 11211,
    5900, 445, 139, 135, 88, 389, 636, 3268, 3269, 1433, 1521, 9200, 9300,
];

/// 按高频端口优先级对端口列表排序：高频端口排在前面，其余按端口号排序
///
/// RustScan 按传入的端口顺序扫描，因此该排序能让高频端口最先出结果。
fn sort_ports_by_frequency(ports: &mut [u16]) {
    let high_freq_set: HashSet<u16> = HIGH_FREQUENCY_PORTS.iter().copied().collect();
    ports.sort_by_key(|p| {
        if high_freq_set.contains(p) {
            (0, *p)
        } else {
            (1, *p)
        }
    });
}

/// 常见端口服务映射
pub fn get_common_services() -> HashMap<u16, &'static str> {
    let mut map = HashMap::new();
    // TCP 服务
    map.insert(20, "ftp-data");
    map.insert(21, "ftp");
    map.insert(22, "ssh");
    map.insert(23, "telnet");
    map.insert(25, "smtp");
    map.insert(53, "dns");
    map.insert(80, "http");
    map.insert(110, "pop3");
    map.insert(143, "imap");
    map.insert(443, "https");
    map.insert(445, "smb");
    map.insert(993, "imaps");
    map.insert(995, "pop3s");
    map.insert(1433, "ms-sql");
    map.insert(1521, "oracle");
    map.insert(3306, "mysql");
    map.insert(3389, "rdp");
    map.insert(5432, "postgresql");
    map.insert(5900, "vnc");
    map.insert(6379, "redis");
    map.insert(8080, "http-proxy");
    map.insert(8443, "https-alt");
    map.insert(27017, "mongodb");
    // UDP 服务
    map.insert(53, "dns");
    map.insert(67, "dhcp");
    map.insert(68, "dhcp-client");
    map.insert(69, "tftp");
    map.insert(123, "ntp");
    map.insert(161, "snmp");
    map.insert(162, "snmptrap");
    map.insert(500, "ike");
    map.insert(514, "syslog");
    map
}

/// 高性能端口扫描器
///
/// TCP 端口发现委托给 [`RustScanEngine`]，本结构只保留 UDP 扫描、Banner 抓取、
/// 存活探测与结果聚合等能力。
pub struct PortScanner {
    /// 默认并发数（映射为 RustScan 的 batch_size）
    concurrency: usize,
    /// TCP 超时时间
    tcp_timeout: Duration,
    /// UDP 超时时间
    udp_timeout: Duration,
    /// 服务映射表
    services: HashMap<u16, &'static str>,
}

/// 进度上报上下文：集中拼装 [`ScanProgress`]，避免多处重复计算
#[derive(Clone)]
struct ProgressCtx {
    target: String,
    target_idx: usize,
    total_targets: usize,
    /// 单个目标需要扫描的端口数
    ports_per_target: usize,
    /// 全部目标需要扫描的端口总数
    total_scans: usize,
    start_time: Instant,
}

impl ProgressCtx {
    fn new(
        target: String,
        target_idx: usize,
        total_targets: usize,
        ports_per_target: usize,
        total_scans: usize,
        start_time: Instant,
    ) -> Self {
        Self {
            target,
            target_idx,
            total_targets,
            ports_per_target,
            total_scans,
            start_time,
        }
    }

    /// 生成一份进度快照
    ///
    /// * `scanned_in_target`：当前目标内已完成的端口数
    /// * `open_found`：当前目标内已发现的开放端口数
    fn snapshot(&self, scanned_in_target: usize, open_found: usize) -> ScanProgress {
        let scanned =
            (self.target_idx * self.ports_per_target + scanned_in_target).min(self.total_scans);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let scan_rate = if elapsed > 0.0 {
            scanned as f64 / elapsed
        } else {
            0.0
        };
        let estimated_remaining_seconds = if scan_rate > 0.0 {
            ((self.total_scans.saturating_sub(scanned)) as f64 / scan_rate) as u64
        } else {
            0
        };
        let progress_percent = if self.total_scans > 0 {
            (scanned as f64 / self.total_scans as f64) * 100.0
        } else {
            0.0
        };

        ScanProgress {
            current_target_index: self.target_idx,
            total_targets: self.total_targets,
            current_target: self.target.clone(),
            scanned_ports: scanned,
            total_ports: self.total_scans,
            open_ports_found: open_found,
            progress_percent,
            scan_rate,
            estimated_remaining_seconds,
        }
    }
}

impl PortScanner {
    /// 创建扫描器实例
    pub fn new(concurrency: usize, tcp_timeout_ms: u64, udp_timeout_ms: u64) -> Self {
        Self {
            concurrency: concurrency.max(1),
            tcp_timeout: Duration::from_millis(tcp_timeout_ms.max(1)),
            udp_timeout: Duration::from_millis(udp_timeout_ms.max(1)),
            services: get_common_services(),
        }
    }

    /// 把结果推入实时通道，并按 `include_closed` 决定是否保留
    ///
    /// 返回 `Some(result)` 表示该结果应计入本次扫描的返回集合。
    ///
    /// 使用带背压的 `send().await` 而非 `try_send()`：全端口扫描开启
    /// `include_closed` 时会在阶段三一次性补齐数万条关闭端口结果，
    /// 通道（容量见 ipc.rs）瞬间被打满，`try_send` 会把装不下的结果静默丢弃，
    /// 导致客户端拿到的结果数远少于引擎实际产出（曾出现 65535 条只送达 20000 条）。
    /// 改为 `await` 后，扫描速率由下游消费速度决定，保证不丢结果；
    /// 若接收端已断开，`send` 会立即返回 Err，不会造成任务悬挂。
    async fn push_result(
        result_tx: &mpsc::Sender<PortScanResult>,
        result: PortScanResult,
        include_closed: bool,
    ) -> Option<PortScanResult> {
        if !include_closed && result.status != "开放" {
            return None;
        }
        if let Err(e) = result_tx.send(result.clone()).await {
            debug!("结果发送失败 (通道已关闭): {}", e);
        }
        Some(result)
    }

    /// 执行批量扫描
    pub async fn scan_batch(
        &self,
        config: ScanConfig,
        progress_tx: mpsc::Sender<ScanProgress>,
        result_tx: mpsc::Sender<PortScanResult>,
    ) -> Result<Vec<PortScanResult>> {
        // 可选：扫描前执行 Ping 存活探测
        let targets_to_scan = if config.enable_ping_probe.unwrap_or(false) {
            let alive = Self::ping_probe(&config.targets, 1000).await;
            info!(
                "Ping 探测完成: 存活 {}/{} 目标",
                alive.len(),
                config.targets.len()
            );
            alive
        } else {
            config.targets.clone()
        };

        let total_targets = targets_to_scan.len();

        // 高频端口优先排序：更快发现开放端口，提升用户体验
        let mut sorted_ports = config.ports.clone();
        sort_ports_by_frequency(&mut sorted_ports);
        let total_ports = sorted_ports.len();
        let total_scans = total_targets * total_ports;

        info!(
            "scan_batch 入口: targets={}, ports={}, protocol={}, detect_service={}, total_scans={}",
            total_targets, total_ports, config.protocol, config.detect_service, total_scans
        );

        if total_targets == 0 || total_ports == 0 {
            info!("scan_batch 提前返回: 目标或端口为空");
            return Ok(Vec::new());
        }

        // 根据请求参数覆盖默认并发控制
        let default_capacity = self.concurrency;
        let tcp_concurrency = config
            .tcp_concurrency
            .map(|c| c as usize)
            .unwrap_or(default_capacity)
            .max(1);
        let udp_concurrency = config
            .udp_concurrency
            .map(|c| c as usize)
            .unwrap_or(default_capacity)
            .max(1);
        let banner_concurrency = (tcp_concurrency / 4).max(1);
        let retry_count = config.retry_count.unwrap_or(0);

        let start_time = Instant::now();
        let mut open_count = 0;
        let mut all_results = Vec::new();

        // 预解析所有目标IP: 任一无效则整体失败, 避免"部分目标已扫描后才报错"的非原子行为
        let parsed_targets: Vec<(String, IpAddr)> = targets_to_scan
            .iter()
            .map(|t| {
                t.parse::<IpAddr>()
                    .map(|ip| (t.clone(), ip))
                    .with_context(|| format!("无效的IP地址: {}", t))
            })
            .collect::<Result<Vec<_>>>()?;

        for (target_idx, (target, target_ip)) in parsed_targets.into_iter().enumerate() {
            info!(
                "扫描目标 [{}/{}]: {}",
                target_idx + 1,
                total_targets,
                target
            );

            // 并发扫描所有端口 (实时 progress + result)
            let results = self
                .scan_target_ports_with_progress(
                    target.clone(),
                    target_ip,
                    &sorted_ports,
                    &config.protocol,
                    config.detect_service,
                    config.include_closed,
                    progress_tx.clone(),
                    result_tx.clone(),
                    target_idx,
                    total_targets,
                    total_ports,
                    total_scans,
                    start_time,
                    tcp_concurrency,
                    udp_concurrency,
                    banner_concurrency,
                    retry_count,
                )
                .await?;

            // 累计本目标开放端口到总数
            let open_in_target = results.iter().filter(|r| r.status == "开放").count();
            open_count += open_in_target;

            // 累计结果
            for r in &results {
                all_results.push(r.clone());
            }

            // 发送最终进度报告
            let elapsed = start_time.elapsed().as_secs_f64();
            let scanned = (target_idx + 1) * total_ports;
            let rate = if elapsed > 0.0 {
                scanned as f64 / elapsed
            } else {
                0.0
            };
            let remaining = if rate > 0.0 {
                ((total_scans.saturating_sub(scanned)) as f64 / rate) as u64
            } else {
                0
            };

            let progress = ScanProgress {
                current_target_index: target_idx,
                total_targets,
                current_target: target.clone(),
                scanned_ports: scanned,
                total_ports: total_scans,
                open_ports_found: open_count,
                progress_percent: (scanned as f64 / total_scans as f64) * 100.0,
                scan_rate: rate,
                estimated_remaining_seconds: remaining,
            };
            info!(
                "[scan_batch progress] target={} scanned={}/{} open={}",
                target, scanned, total_scans, open_count
            );
            if let Err(e) = progress_tx.try_send(progress) {
                debug!("[scan_batch] progress 发送失败 (channel 满或已关闭): {}", e);
            }
        }

        info!(
            "scan_batch 完成: 总结果数={}, 总开放端口数={}",
            all_results.len(),
            open_count
        );
        Ok(all_results)
    }

    /// 扫描单个目标的多个端口 (支持实时 progress 上报)
    ///
    /// * TCP：交给 RustScan 引擎批量发现开放端口，再对开放端口做可选 Banner 抓取
    /// * UDP：本模块逐端口探测（RustScan 的 UDP 依赖内置 payload 表，语义与本项目不一致）
    /// * both：先做 TCP 发现，仅对 TCP 未开放的端口再做 UDP 探测
    #[allow(clippy::too_many_arguments)]
    async fn scan_target_ports_with_progress(
        &self,
        target_str: String,
        target_ip: IpAddr,
        ports: &[u16],
        protocol: &str,
        detect_service: bool,
        include_closed: bool,
        progress_tx: mpsc::Sender<ScanProgress>,
        result_tx: mpsc::Sender<PortScanResult>,
        target_idx: usize,
        total_targets: usize,
        total_ports: usize,
        total_scans: usize,
        start_time: Instant,
        tcp_concurrency: usize,
        udp_concurrency: usize,
        banner_concurrency: usize,
        retry_count: u32,
    ) -> Result<Vec<PortScanResult>> {
        let proto = protocol.to_ascii_lowercase();
        let do_tcp = proto == "tcp" || proto == "both";
        let do_udp = proto == "udp" || proto == "both";

        let ctx = ProgressCtx::new(
            target_str.clone(),
            target_idx,
            total_targets,
            total_ports,
            total_scans,
            start_time,
        );

        let banner_sem = if detect_service {
            Some(Arc::new(Semaphore::new(banner_concurrency.max(1))))
        } else {
            None
        };
        let banner_timeout = (self.tcp_timeout / 2).max(Duration::from_millis(50));

        let mut results: Vec<PortScanResult> = Vec::new();
        let mut tcp_open: HashSet<u16> = HashSet::new();
        let mut udp_open: HashSet<u16> = HashSet::new();
        // 记录 UDP 阶段已产出结果的端口（含关闭），避免阶段三重复补齐造成重复结果
        let mut udp_scanned: HashSet<u16> = HashSet::new();

        // ---------- 阶段一：RustScan 批量 TCP 端口发现 ----------
        if do_tcp {
            let engine = RustScanEngine::new(
                tcp_concurrency,
                self.tcp_timeout.as_millis() as u64,
                retry_count.saturating_add(1),
            );
            info!(
                "[RustScan] target={} 开始发现 {} 个 TCP 端口 (batch_size={}, timeout={}ms, tries={})",
                target_str,
                ports.len(),
                engine.batch_size(),
                self.tcp_timeout.as_millis(),
                retry_count.saturating_add(1)
            );

            let tcp_start = Instant::now();
            let progress_tx_cb = progress_tx.clone();
            let ctx_cb = ctx.clone();
            let open_ports = engine
                .scan_open_tcp_ports(target_ip, ports, move |scanned, open_found| {
                    if let Err(e) = progress_tx_cb.try_send(ctx_cb.snapshot(scanned, open_found)) {
                        debug!("[RustScan] 进度发送失败 (channel 满或已关闭): {}", e);
                    }
                })
                .await
                .with_context(|| format!("RustScan 引擎扫描 {} 失败", target_ip))?;

            // RustScan 不提供单端口耗时：把整个 TCP 发现阶段的耗时平摊到发现的开放端口上，
            // 使单条结果的 scan_time_ms 与 Complete 汇总耗时都能反映真实扫描开销
            let elapsed_ms = tcp_start.elapsed().as_millis() as u64;
            let avg_port_ms = if open_ports.is_empty() {
                0
            } else {
                (elapsed_ms / open_ports.len() as u64).max(1)
            };

            for &port in &open_ports {
                tcp_open.insert(port);
                let service = self
                    .services
                    .get(&port)
                    .copied()
                    .unwrap_or("unknown")
                    .to_string();

                let (version, banner) = if detect_service {
                    let _permit = match &banner_sem {
                        Some(sem) => sem.clone().acquire_owned().await.ok(),
                        None => None,
                    };
                    Self::grab_banner_tcp(SocketAddr::new(target_ip, port), banner_timeout).await
                } else {
                    (String::new(), String::new())
                };

                let result = PortScanResult {
                    target_ip: target_str.clone(),
                    port,
                    protocol: "TCP".to_string(),
                    status: "开放".to_string(),
                    service,
                    version,
                    banner,
                    scan_time_ms: avg_port_ms,
                };
                if let Some(r) = Self::push_result(&result_tx, result, include_closed).await {
                    results.push(r);
                }
            }

            info!(
                "[RustScan] target={} TCP 发现完成: 开放 {} 个端口",
                target_str,
                tcp_open.len()
            );
            if let Err(e) = progress_tx.try_send(ctx.snapshot(ports.len(), tcp_open.len())) {
                debug!(
                    "[scan_target_ports_with_progress] TCP 阶段进度发送失败: {}",
                    e
                );
            }
        }

        // ---------- 阶段二：UDP 探测 ----------
        if do_udp {
            // both 模式下，TCP 已确认开放的端口不再做 UDP 探测（与内置引擎语义一致）
            let udp_ports: Vec<u16> = if do_tcp {
                ports
                    .iter()
                    .copied()
                    .filter(|p| !tcp_open.contains(p))
                    .collect()
            } else {
                ports.to_vec()
            };

            if !udp_ports.is_empty() {
                let udp_timeout_ms = Arc::new(AtomicU64::new(self.udp_timeout.as_millis() as u64));
                let semaphore = Arc::new(Semaphore::new(udp_concurrency.max(1)));
                let update_interval = (udp_ports.len() / 20).max(1);
                let mut tasks = JoinSet::new();
                let mut completed = 0usize;

                for &port in &udp_ports {
                    let permit = semaphore.clone().acquire_owned().await?;
                    let target = target_str.clone();
                    let timeout_ms = udp_timeout_ms.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        Self::scan_udp_port(target, target_ip, port, timeout_ms).await
                    });
                }

                while let Some(res) = tasks.join_next().await {
                    completed += 1;
                    match res {
                        Ok(result) => {
                            udp_scanned.insert(result.port);
                            if result.status == "开放" {
                                udp_open.insert(result.port);
                            }
                            if let Some(r) =
                                Self::push_result(&result_tx, result, include_closed).await
                            {
                                results.push(r);
                            }
                        }
                        Err(e) => warn!("UDP 扫描任务执行错误: {}", e),
                    }

                    if completed % update_interval == 0 || completed == udp_ports.len() {
                        let scanned_in_target = if do_tcp { ports.len() } else { completed };
                        if let Err(e) = progress_tx.try_send(
                            ctx.snapshot(scanned_in_target, tcp_open.len() + udp_open.len()),
                        ) {
                            debug!(
                                "[scan_target_ports_with_progress] UDP 阶段进度发送失败: {}",
                                e
                            );
                        }
                    }
                }
            }
        }

        // ---------- 阶段三：按需补齐关闭端口的结果 ----------
        // RustScan 只返回开放端口，无法区分“关闭”与“过滤”，统一标记为关闭
        if include_closed {
            let mut known_open: HashSet<u16> = tcp_open.clone();
            known_open.extend(udp_open.iter().copied());
            for &port in ports {
                // 已开放，或 UDP 阶段已产出过结果（含关闭）的端口跳过，避免重复
                if known_open.contains(&port) || udp_scanned.contains(&port) {
                    continue;
                }
                let result = PortScanResult {
                    target_ip: target_str.clone(),
                    port,
                    protocol: if do_tcp {
                        "TCP".to_string()
                    } else {
                        "UDP".to_string()
                    },
                    status: "关闭".to_string(),
                    service: String::new(),
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms: 0,
                };
                if let Some(r) = Self::push_result(&result_tx, result, true).await {
                    results.push(r);
                }
            }
        }

        info!(
            "scan_target_ports_with_progress 完成: target={}, results={}, tcp_open={}, udp_open={}",
            target_str,
            results.len(),
            tcp_open.len(),
            udp_open.len()
        );
        Ok(results)
    }

    /// UDP 端口扫描 (异步)
    async fn scan_udp_port(
        target: String,
        ip: IpAddr,
        port: u16,
        timeout_ms: Arc<AtomicU64>,
    ) -> PortScanResult {
        let addr = SocketAddr::new(ip, port);
        let service = get_common_services()
            .get(&port)
            .copied()
            .unwrap_or("unknown")
            .to_string();

        // 读取当前 UDP 超时
        let timeout = Duration::from_millis(timeout_ms.load(Ordering::Relaxed));

        // 记录扫描开始时间
        let scan_start = Instant::now();

        // UDP 扫描: 发送空数据包并等待响应
        let result = tokio::time::timeout(timeout, async {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(&addr).await?;
            socket.send(&[]).await?;

            let mut buf = [0u8; 1024];
            match socket.recv(&mut buf).await {
                Ok(len) => Ok::<_, std::io::Error>(Some(buf[..len].to_vec())),
                Err(_) => Ok::<_, std::io::Error>(None),
            }
        })
        .await;

        // 计算扫描耗时
        let scan_time_ms = scan_start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(Some(_))) => {
                // 收到响应 - 端口开放
                PortScanResult {
                    target_ip: target,
                    port,
                    protocol: "UDP".to_string(),
                    status: "开放".to_string(),
                    service,
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms,
                }
            }
            Ok(Ok(None)) | Ok(Err(_)) => {
                // 无响应或错误 - 可能关闭或过滤
                PortScanResult {
                    target_ip: target,
                    port,
                    protocol: "UDP".to_string(),
                    status: "关闭".to_string(),
                    service: String::new(),
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms,
                }
            }
            Err(_) => {
                // 超时
                PortScanResult {
                    target_ip: target,
                    port,
                    protocol: "UDP".to_string(),
                    status: "过滤".to_string(),
                    service: String::new(),
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms,
                }
            }
        }
    }

    /// TCP Banner 抓取
    async fn grab_banner_tcp(addr: SocketAddr, timeout: Duration) -> (String, String) {
        let result = tokio::time::timeout(timeout, async {
            let mut stream = tokio::net::TcpStream::connect(&addr).await?;

            // 发送探测请求
            let probe = b"HEAD / HTTP/1.0\r\n\r\n";
            stream.write_all(probe).await?;

            // 读取响应
            let mut buf = [0u8; 512];
            let len = stream.read(&mut buf).await?;
            let banner = String::from_utf8_lossy(&buf[..len]).to_string();

            Ok::<String, anyhow::Error>(banner)
        })
        .await;

        match result {
            Ok(Ok(banner)) => {
                // 解析版本信息
                let version = Self::parse_version(&banner);
                (
                    version,
                    banner.lines().take(3).collect::<Vec<_>>().join("\n"),
                )
            }
            _ => (String::new(), String::new()),
        }
    }

    /// 从 Banner 解析服务版本
    fn parse_version(banner: &str) -> String {
        // 常见模式匹配
        let patterns = [
            ("Server: ", "\r\n"),
            ("HTTP/", " "),
            ("SSH-", " "),
            ("FTP", " "),
        ];

        for (prefix, suffix) in patterns {
            if let Some(start) = banner.find(prefix) {
                let rest = &banner[start + prefix.len()..];
                if let Some(end) = rest.find(suffix) {
                    return rest[..end].to_string();
                }
                return rest.split_whitespace().next().unwrap_or("").to_string();
            }
        }
        String::new()
    }

    /// 对目标列表并发执行 Ping 存活探测
    async fn ping_probe(targets: &[String], timeout_ms: u64) -> Vec<String> {
        let mut set = JoinSet::new();
        for target in targets {
            let target = target.clone();
            set.spawn(async move {
                let alive = Self::ping_host(&target, timeout_ms).await;
                (target, alive)
            });
        }

        let mut alive_targets = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok((target, true)) = res {
                alive_targets.push(target);
            }
        }
        alive_targets
    }

    /// 使用系统 ping 命令探测单个目标是否存活
    async fn ping_host(target: &str, timeout_ms: u64) -> bool {
        let timeout = Duration::from_millis(timeout_ms);
        let cmd_future = async {
            #[cfg(windows)]
            {
                tokio::process::Command::new("ping")
                    .args(["-n", "1", "-w", &timeout_ms.to_string(), target])
                    .output()
                    .await
            }
            #[cfg(not(windows))]
            {
                tokio::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", target])
                    .output()
                    .await
            }
        };

        match tokio::time::timeout(timeout + Duration::from_secs(2), cmd_future).await {
            Ok(Ok(output)) => {
                if !output.status.success() {
                    return false;
                }
                let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
                stdout.contains("ttl=") || stdout.contains("ttl ")
            }
            _ => false,
        }
    }
}

/// 常用端口列表
///
/// 说明：当前主流程的端口由 IPC 请求直接提供，本函数保留供命令行/未来复用。
#[allow(dead_code)]
pub fn get_common_ports() -> Vec<u16> {
    vec![
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 27017, // UDP 常用端口
        53, 67, 68, 69, 123, 161, 162, 500, 514,
    ]
}

/// 解析端口范围字符串 (如 "1-1000" 或 "22,80,443")
///
/// 说明：当前主流程的端口由 IPC 请求直接提供，本函数保留供命令行/未来复用。
#[allow(dead_code)]
pub fn parse_ports(port_str: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // 范围解析
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow::anyhow!("无效的端口范围: {}", part));
            }
            let start: u16 = range[0].parse()?;
            let end: u16 = range[1].parse()?;
            for p in start..=end {
                ports.push(p);
            }
        } else {
            // 单个端口
            ports.push(part.parse()?);
        }
    }

    Ok(ports)
}

/// 解析目标 IP 范围 (如 "192.168.1.1-192.168.1.255" 或 CIDR)
///
/// 说明：当前主流程的目标由 IPC 请求直接提供，本函数保留供命令行/未来复用。
#[allow(dead_code)]
pub fn parse_targets(target_str: &str) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for part in target_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('/') {
            // CIDR 格式 (简化处理)
            let cidr: Vec<&str> = part.split('/').collect();
            if cidr.len() != 2 {
                return Err(anyhow::anyhow!("无效的CIDR格式: {}", part));
            }
            let base_ip: Ipv4Addr = cidr[0].parse()?;
            let mask_bits: u32 = cidr[1].parse()?;
            // 掩码位数必须在 0..=32 之间，否则位移/减法会溢出
            if mask_bits > 32 {
                return Err(anyhow::anyhow!(
                    "无效的CIDR掩码位数: {} (应在0-32之间)",
                    mask_bits
                ));
            }

            // 计算IP范围
            let base: u32 = u32::from(base_ip);
            let host_bits = 32 - mask_bits;
            // host_bits == 32 时 1u32 << 32 会溢出，单独处理
            let count: u32 = if host_bits >= 32 {
                u32::MAX
            } else {
                1u32 << host_bits
            };

            for i in 0..count.min(256) {
                // 限制最多256个
                let ip = Ipv4Addr::from(base.saturating_add(i));
                targets.push(ip.to_string());
            }
        } else if part.contains('-') {
            // 范围格式
            let range: Vec<&str> = part.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow::anyhow!("无效的IP范围: {}", part));
            }
            let start: Ipv4Addr = range[0].parse()?;
            let end: Ipv4Addr = range[1].parse()?;

            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);
            let upper = end_u32.min(start_u32.saturating_add(255)); // 限制最多256个

            for i in start_u32..=upper {
                let ip = Ipv4Addr::from(i);
                targets.push(ip.to_string());
            }
        } else {
            // 单个IP
            targets.push(part.to_string());
        }
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn sort_ports_puts_high_frequency_first() {
        let mut ports = vec![12345u16, 22, 9999, 443, 80];
        sort_ports_by_frequency(&mut ports);
        assert_eq!(ports, vec![22, 80, 443, 9999, 12345]);
    }

    #[test]
    fn sort_ports_keeps_low_frequency_ascending() {
        let mut ports = vec![60000u16, 40000, 50000];
        sort_ports_by_frequency(&mut ports);
        assert_eq!(ports, vec![40000, 50000, 60000]);
    }

    #[test]
    fn parse_version_extracts_server_header() {
        let v = PortScanner::parse_version("Server: RustScanFixture/1.0\r\nContent-Length: 0\r\n");
        assert_eq!(v, "RustScanFixture/1.0");
    }

    #[test]
    fn parse_version_extracts_http_version() {
        let v = PortScanner::parse_version("HTTP/1.1 200 OK\r\n");
        assert_eq!(v, "1.1");
    }

    #[test]
    fn parse_version_returns_empty_for_plain_banner() {
        assert_eq!(PortScanner::parse_version("HELLO-PLAIN"), "");
        assert_eq!(PortScanner::parse_version(""), "");
    }

    #[test]
    fn common_services_maps_known_ports() {
        let map = get_common_services();
        assert_eq!(map.get(&80), Some(&"http"));
        assert_eq!(map.get(&443), Some(&"https"));
        assert_eq!(map.get(&445), Some(&"smb"));
        assert_eq!(map.get(&6379), Some(&"redis"));
    }

    #[test]
    fn progress_snapshot_computes_percent_and_totals() {
        let ctx = ProgressCtx::new("127.0.0.1".to_string(), 1, 2, 100, 200, Instant::now());
        let snap = ctx.snapshot(50, 3);
        assert_eq!(snap.current_target_index, 1);
        assert_eq!(snap.total_targets, 2);
        assert_eq!(snap.scanned_ports, 150);
        assert_eq!(snap.total_ports, 200);
        assert_eq!(snap.open_ports_found, 3);
        assert!((snap.progress_percent - 75.0).abs() < 1e-9);
    }

    #[test]
    fn progress_snapshot_handles_zero_total() {
        let ctx = ProgressCtx::new("127.0.0.1".to_string(), 0, 0, 0, 0, Instant::now());
        let snap = ctx.snapshot(0, 0);
        assert_eq!(snap.progress_percent, 0.0);
        assert_eq!(snap.estimated_remaining_seconds, 0);
    }

    #[test]
    fn parse_ports_supports_ranges_and_lists() {
        assert_eq!(parse_ports("1-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-3,80").unwrap(), vec![1, 2, 3, 80]);
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn parse_targets_supports_single_cidr_and_range() {
        assert_eq!(
            parse_targets("10.0.0.1").unwrap(),
            vec!["10.0.0.1".to_string()]
        );
        assert_eq!(parse_targets("10.0.0.0/30").unwrap().len(), 4);
        assert_eq!(parse_targets("1.2.3.4-1.2.3.6").unwrap().len(), 3);
    }

    #[test]
    fn parse_targets_rejects_invalid_mask_without_panic() {
        // 掩码 > 32 曾会触发 32 - mask_bits 的减法溢出 panic，修复后应返回错误
        assert!(parse_targets("10.0.0.0/64").is_err());
    }

    #[test]
    fn parse_targets_caps_range_and_avoids_overflow() {
        // 上限 255.255.255.255 时 start + 255 曾会溢出，修复后应正常返回 1 个地址
        assert_eq!(
            parse_targets("255.255.255.255-255.255.255.255")
                .unwrap()
                .len(),
            1
        );
        // /0 覆盖全部地址，但应被限制为最多 256 个
        assert_eq!(parse_targets("0.0.0.0/0").unwrap().len(), 256);
    }
}
