//! 高性能端口扫描模块 v1.0.2.1
//! 使用 Tokio 异步运行时实现并发扫描
//! 性能优化: 信号量限流、零拷贝、批量IO

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as TokioMutex, Semaphore};
use tokio::task::JoinSet;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tracing::{info, debug};

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
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3306, 3389, 5432, 6379,
    27017, 11211, 5900, 445, 139, 135, 88, 389, 636, 3268, 3269, 1433, 1521, 9200, 9300,
];

/// 按高频端口优先级对端口列表排序：高频端口排在前面，其余按端口号排序
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
pub struct PortScanner {
    /// 并发控制信号量
    semaphore: Arc<Semaphore>,
    /// 默认并发数
    concurrency: usize,
    /// TCP 超时时间
    tcp_timeout: Duration,
    /// UDP 超时时间
    udp_timeout: Duration,
    /// 服务映射表
    services: HashMap<u16, &'static str>,
    /// 每个目标的 banner 抓取并发上限（为主并发数的 1/4，避免占满全部并发）
    banner_concurrency: usize,
    /// 每个目标的 banner 抓取信号量缓存
    banner_semaphores: Arc<TokioMutex<HashMap<String, Arc<Semaphore>>>>,
}

/// 自适应超时状态：基于前 20 个已完成端口的平均 RTT 一次性调整后续超时
#[derive(Clone)]
struct AdaptiveTimeout {
    base_timeout_ms: u64,
    timeout_ms: Arc<AtomicU64>,
    adjusted: Arc<AtomicBool>,
    rtt_sum: Arc<AtomicU64>,
    rtt_count: Arc<AtomicUsize>,
}

impl AdaptiveTimeout {
    fn new(base_timeout_ms: u64) -> Self {
        Self {
            base_timeout_ms,
            timeout_ms: Arc::new(AtomicU64::new(base_timeout_ms)),
            adjusted: Arc::new(AtomicBool::new(false)),
            rtt_sum: Arc::new(AtomicU64::new(0)),
            rtt_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn get_timeout_ms(&self) -> Arc<AtomicU64> {
        self.timeout_ms.clone()
    }

    /// 上报一个端口的扫描耗时（ms）。累计满 20 个后计算 avg_rtt 并只调整一次。
    fn report_rtt(&self, rtt_ms: u64) {
        if self.adjusted.load(Ordering::Relaxed) {
            return;
        }
        let count = self.rtt_count.fetch_add(1, Ordering::Relaxed);
        if count >= 20 {
            return;
        }
        self.rtt_sum.fetch_add(rtt_ms, Ordering::Relaxed);
        if count == 19 {
            let sum = self.rtt_sum.load(Ordering::Relaxed);
            let avg = sum / 20;
            let base = self.base_timeout_ms;
            let new_timeout = if avg > base / 2 {
                ((base as f64 * 1.5) as u64).min(2000)
            } else if avg < base / 4 {
                ((base as f64 * 0.8) as u64).max(100)
            } else {
                base
            };
            if new_timeout != base {
                self.timeout_ms.store(new_timeout, Ordering::Relaxed);
                eprintln!(
                    "[adaptive] timeout adjusted to {} ms (avg_rtt={} ms, base={})",
                    new_timeout, avg, base
                );
            }
            self.adjusted.store(true, Ordering::Relaxed);
        }
    }
}

/// 自适应并发状态：基于最近 50 个端口的成功率动态调整并发信号量
#[derive(Clone)]
struct AdaptiveConcurrency {
    initial: usize,
    current: Arc<AtomicUsize>,
    semaphore: Arc<TokioMutex<Arc<Semaphore>>>,
    window: Arc<TokioMutex<VecDeque<bool>>>,
    since_adjustment: Arc<AtomicUsize>,
}

impl AdaptiveConcurrency {
    fn new(initial: usize) -> Self {
        Self {
            initial,
            current: Arc::new(AtomicUsize::new(initial)),
            semaphore: Arc::new(TokioMutex::new(Arc::new(Semaphore::new(initial)))),
            window: Arc::new(TokioMutex::new(VecDeque::with_capacity(50))),
            since_adjustment: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 获取一个当前信号量的 owned permit
    async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        let sem = { self.semaphore.lock().await.clone() };
        Ok(sem.acquire_owned().await?)
    }

    /// 上报单个端口的成功/失败状态，并根据滑动窗口调整并发
    async fn report_result(&self, success: bool) {
        let (len, success_count) = {
            let mut window = self.window.lock().await;
            if window.len() == 50 {
                window.pop_front();
            }
            window.push_back(success);
            let success_count = window.iter().filter(|&&b| b).count();
            (window.len(), success_count)
        };

        self.since_adjustment.fetch_add(1, Ordering::Relaxed);
        let since = self.since_adjustment.load(Ordering::Relaxed);
        let current = self.current.load(Ordering::Relaxed);

        if len < 50 {
            return;
        }

        let rate = success_count as f64 / len as f64;
        let new_current = if rate < 0.7 {
            Some((current / 2).max(10))
        } else if rate > 0.95 && since >= 100 {
            Some(((current as f64 * 1.2) as usize).min(self.initial))
        } else {
            None
        };

        if let Some(new) = new_current {
            if new != current {
                self.current.store(new, Ordering::Relaxed);
                self.since_adjustment.store(0, Ordering::Relaxed);
                let mut guard = self.semaphore.lock().await;
                *guard = Arc::new(Semaphore::new(new));
                drop(guard);
                eprintln!("[adaptive] concurrency adjusted to {}", new);
            }
        }
    }
}

impl PortScanner {
    /// 创建扫描器实例
    pub fn new(concurrency: usize, tcp_timeout_ms: u64, udp_timeout_ms: u64) -> Self {
        let banner_concurrency = (concurrency / 4).max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(concurrency)),
            concurrency,
            tcp_timeout: Duration::from_millis(tcp_timeout_ms),
            udp_timeout: Duration::from_millis(udp_timeout_ms),
            services: get_common_services(),
            banner_concurrency,
            banner_semaphores: Arc::new(TokioMutex::new(HashMap::new())),
        }
    }

    /// 获取（按需创建）针对某个目标的 banner 抓取信号量
    async fn banner_semaphore_for(&self, target: &str) -> Arc<Semaphore> {
        let mut map = self.banner_semaphores.lock().await;
        map.entry(target.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.banner_concurrency)))
            .clone()
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

        // 根据请求参数覆盖默认并发控制
        let default_capacity = self.concurrency;
        let tcp_concurrency = config
            .tcp_concurrency
            .map(|c| c as usize)
            .unwrap_or(default_capacity);
        let udp_concurrency = config
            .udp_concurrency
            .map(|c| c as usize)
            .unwrap_or(default_capacity);
        let banner_concurrency = (tcp_concurrency / 4).max(1);
        let retry_count = config.retry_count.unwrap_or(0);
        // 当 TCP 并发较高时启用 socket 级优化（禁用 Nagle、SO_REUSEADDR）
        let optimize_socket = tcp_concurrency >= 100;

        let start_time = Instant::now();
        let mut open_count = 0;
        let mut all_results = Vec::new();

        for (target_idx, target) in targets_to_scan.iter().enumerate() {
            let target_ip: IpAddr = target.parse()
                .with_context(|| format!("无效的IP地址: {}", target))?;

            info!("扫描目标 [{}/{}]: {}", target_idx + 1, total_targets, target);

            // 并发扫描所有端口 (实时 progress + result)
            let results = self.scan_target_ports_with_progress(
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
                optimize_socket,
            ).await?;

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
            let rate = scanned as f64 / elapsed;
            let remaining = if rate > 0.0 {
                ((total_scans - scanned) as f64 / rate) as u64
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
                eprintln!("[scan_batch] progress 发送失败 (channel 满或已关闭): {}", e);
            }
        }

        info!("scan_batch 完成: 总结果数={}, 总开放端口数={}", all_results.len(), open_count);
        Ok(all_results)
    }

    /// 扫描单个目标的多个端口
    async fn scan_target_ports(
        &self,
        target_str: String,
        target_ip: IpAddr,
        ports: &[u16],
        protocol: &str,
        detect_service: bool,
        include_closed: bool,
    ) -> Result<Vec<PortScanResult>> {
        let mut tasks = JoinSet::new();
        let semaphore = self.semaphore.clone();
        let tcp_timeout_ms = Arc::new(AtomicU64::new(self.tcp_timeout.as_millis() as u64));
        let udp_timeout_ms = Arc::new(AtomicU64::new(self.udp_timeout.as_millis() as u64));
        let protocol_owned = protocol.to_string();
        let banner_sem = if detect_service {
            Some(self.banner_semaphore_for(&target_str).await)
        } else {
            None
        };

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let target = target_str.clone();
            let proto = protocol_owned.clone();
            let banner_sem = banner_sem.clone();
            let tcp_timeout_ms = tcp_timeout_ms.clone();
            let udp_timeout_ms = udp_timeout_ms.clone();

            tasks.spawn(async move {
                let _permit = permit; // 持有许可直到任务完成

                let start = Instant::now();
                let result = if proto == "tcp" {
                    Self::scan_tcp_port(target, target_ip, port, tcp_timeout_ms, detect_service, banner_sem.clone(), 0, false).await
                } else if proto == "udp" {
                    Self::scan_udp_port(target, target_ip, port, udp_timeout_ms).await
                } else {
                    // both: 先TCP再UDP
                    let tcp_result = Self::scan_tcp_port(target.clone(), target_ip, port, tcp_timeout_ms, detect_service, banner_sem.clone(), 0, false).await;
                    if tcp_result.status == "开放" {
                        tcp_result
                    } else {
                        Self::scan_udp_port(target, target_ip, port, udp_timeout_ms).await
                    }
                };

                let scan_time = start.elapsed().as_millis() as u64;
                PortScanResult {
                    scan_time_ms: scan_time,
                    ..result
                }
            });
        }

        // 收集结果
        let mut results = Vec::new();
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(result) => {
                    if include_closed || result.status == "开放" {
                        results.push(result);
                    }
                }
                Err(e) => {
                    tracing::warn!("任务执行错误: {}", e);
                }
            }
        }

        Ok(results)
    }

    /// 扫描单个目标的多个端口 (支持实时 progress 上报)
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
        optimize_socket: bool,
    ) -> Result<Vec<PortScanResult>> {
        let mut tasks = JoinSet::new();
        let protocol_owned = protocol.to_string();
        let total = ports.len();

        // 自适应超时：基于前 20 个端口的平均 RTT 一次性调整后续超时
        let tcp_adaptive_timeout = AdaptiveTimeout::new(self.tcp_timeout.as_millis() as u64);
        let udp_adaptive_timeout = AdaptiveTimeout::new(self.udp_timeout.as_millis() as u64);

        // 自适应并发：基于最近 50 个端口的成功率动态调整并发信号量
        let tcp_adaptive_concurrency = AdaptiveConcurrency::new(tcp_concurrency);
        let udp_adaptive_concurrency = AdaptiveConcurrency::new(udp_concurrency);

        info!(
            "scan_target_ports_with_progress 入口: target={}, ports={}, protocol={}, detect_service={}, optimize_socket={}",
            target_str, total, protocol, detect_service, optimize_socket
        );

        let banner_sem = if detect_service {
            Some(Arc::new(Semaphore::new(banner_concurrency)))
        } else {
            None
        };

        for &port in ports {
            let proto = protocol_owned.clone();
            let banner_sem = banner_sem.clone();
            let target = target_str.clone();
            let tcp_timeout_ms = tcp_adaptive_timeout.get_timeout_ms();
            let udp_timeout_ms = udp_adaptive_timeout.get_timeout_ms();
            let tcp_adaptive_concurrency = tcp_adaptive_concurrency.clone();
            let udp_adaptive_concurrency = udp_adaptive_concurrency.clone();

            // 按协议类型分别使用 TCP/UDP 自适应并发信号量
            let permit = if proto == "udp" {
                udp_adaptive_concurrency.acquire().await?
            } else {
                tcp_adaptive_concurrency.acquire().await?
            };

            // both 模式下需要额外占用一个 UDP 并发名额
            let udp_permit = if proto == "both" {
                Some(udp_adaptive_concurrency.acquire().await?)
            } else {
                None
            };

            tasks.spawn(async move {
                let _permit = permit;
                let _udp_permit = udp_permit;

                let start = Instant::now();
                let result = if proto == "tcp" {
                    Self::scan_tcp_port(target, target_ip, port, tcp_timeout_ms, detect_service, banner_sem.clone(), retry_count, optimize_socket).await
                } else if proto == "udp" {
                    Self::scan_udp_port(target, target_ip, port, udp_timeout_ms).await
                } else {
                    let tcp_result = Self::scan_tcp_port(target.clone(), target_ip, port, tcp_timeout_ms, detect_service, banner_sem.clone(), retry_count, optimize_socket).await;
                    if tcp_result.status == "开放" {
                        tcp_result
                    } else {
                        Self::scan_udp_port(target, target_ip, port, udp_timeout_ms).await
                    }
                };

                let scan_time = start.elapsed().as_millis() as u64;
                let success = result.status != "过滤";
                let final_result = PortScanResult {
                    scan_time_ms: scan_time,
                    ..result
                };
                (final_result, success)
            });
        }

        // 收集结果 - 实时发送 progress 和 result
        let mut results = Vec::new();
        let mut completed = 0;
        let mut local_open = 0;
        let update_interval = (total / 20).max(1);
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok((result, success)) => {
                    // 自适应超时反馈
                    match result.protocol.as_str() {
                        "TCP" => tcp_adaptive_timeout.report_rtt(result.scan_time_ms),
                        "UDP" => udp_adaptive_timeout.report_rtt(result.scan_time_ms),
                        _ => {}
                    }
                    // 自适应并发反馈
                    match result.protocol.as_str() {
                        "TCP" => tcp_adaptive_concurrency.report_result(success).await,
                        "UDP" => udp_adaptive_concurrency.report_result(success).await,
                        _ => {}
                    }

                    // 实时发送 result
                    if include_closed || result.status == "开放" {
                        if result.status == "开放" {
                            local_open += 1;
                        }
                        info!("[result] {}:{}", result.target_ip, result.port);
                        if let Err(e) = result_tx.try_send(result.clone()) {
                            eprintln!("[scan_target_ports_with_progress] result 发送失败 (channel 满或已关闭): {}", e);
                        }
                        results.push(result);
                    }
                }
                Err(e) => {
                    tracing::warn!("任务执行错误: {}", e);
                }
            }
            completed += 1;

            // 每完成 5% 端口发一次 progress
            if completed % update_interval == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let target_base = target_idx * total_ports;
                let scanned = target_base + completed;
                let rate = if elapsed > 0.0 { scanned as f64 / elapsed } else { 0.0 };
                let remaining = if rate > 0.0 {
                    ((total_scans - scanned) as f64 / rate) as u64
                } else { 0 };

                info!(
                    "[progress] target={} scanned={}/{} open={} percent={:.1}%",
                    target_str, scanned, total_scans, local_open,
                    (scanned as f64 / total_scans as f64) * 100.0
                );
                if let Err(e) = progress_tx.try_send(ScanProgress {
                    current_target_index: target_idx,
                    total_targets,
                    current_target: target_str.clone(),
                    scanned_ports: scanned,
                    total_ports: total_scans,
                    open_ports_found: local_open,  // 进度中的 open 是本目标的
                    progress_percent: (scanned as f64 / total_scans as f64) * 100.0,
                    scan_rate: rate,
                    estimated_remaining_seconds: remaining,
                }) {
                    eprintln!("[scan_target_ports_with_progress] progress 发送失败 (channel 满或已关闭): {}", e);
                }
            }
        }

        info!(
            "scan_target_ports_with_progress 完成: target={}, results={}, open={}",
            target_str, results.len(), local_open
        );
        Ok(results)
    }

    /// 建立 TCP 连接，可选使用 socket2 优化（禁用 Nagle、设置 SO_REUSEADDR）
    async fn connect_tcp(addr: SocketAddr, timeout: Duration, optimize: bool) -> std::io::Result<tokio::net::TcpStream> {
        if optimize {
            match Self::connect_tcp_optimized(addr, timeout).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    debug!("optimized connect failed for {}: {}, falling back", addr, e);
                }
            }
        }
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timeout"))?
    }

    /// 使用 socket2 构建优化后的非阻塞 TCP 连接
    async fn connect_tcp_optimized(addr: SocketAddr, timeout: Duration) -> std::io::Result<tokio::net::TcpStream> {
        use socket2::{Domain, Socket, Type};

        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        socket.set_reuse_address(true)?;

        let bind_addr = SocketAddr::new(
            if addr.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) },
            0,
        );
        socket.bind(&bind_addr.into())?;

        // 非阻塞 connect 通常会返回 EINPROGRESS（Unix）或 WSAEWOULDBLOCK（Windows）
        let _ = socket.connect(&addr.into());

        let std_stream = std::net::TcpStream::from(socket);
        let stream = tokio::net::TcpStream::from_std(std_stream)?;

        tokio::time::timeout(timeout, stream.writable())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timeout"))??;

        // 通过 SO_ERROR 检查连接是否真正建立
        Self::check_socket_error(&stream)?;
        Ok(stream)
    }

    /// 检查 socket 上的 SO_ERROR
    #[cfg(windows)]
    fn check_socket_error(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
        use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};
        let raw = stream.as_raw_socket();
        let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
        let err = sock.take_error()?;
        let _ = sock.into_raw_socket(); // 避免关闭原始句柄
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn check_socket_error(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
        use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
        let raw = stream.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
        let err = sock.take_error()?;
        let _ = sock.into_raw_fd(); // 避免关闭原始句柄
        if let Some(e) = err {
            return Err(e);
        }
        Ok(())
    }

    /// TCP 端口扫描 (异步)
    async fn scan_tcp_port(
        target: String,
        ip: IpAddr,
        port: u16,
        timeout_ms: Arc<AtomicU64>,
        detect_service: bool,
        banner_sem: Option<Arc<Semaphore>>,
        retry_count: u32,
        optimize_socket: bool,
    ) -> PortScanResult {
        let addr = SocketAddr::new(ip, port);
        let service = get_common_services().get(&port).copied().unwrap_or("unknown").to_string();

        debug!("scan_tcp_port: {} {}", ip, port);

        // 读取当前自适应超时（ms），并转换为 Duration
        let timeout = Duration::from_millis(timeout_ms.load(Ordering::Relaxed));

        // 记录扫描开始时间
        let scan_start = Instant::now();

        // 第一次连接探测
        let first_connect = tokio::time::timeout(
            timeout,
            Self::connect_tcp(addr, timeout, optimize_socket)
        ).await;

        let status = match &first_connect {
            Ok(Ok(_)) => "open",
            Ok(Err(_)) => "closed",
            Err(_) => "filtered",
        };
        info!("scan_tcp_port: {} {} -> {}", ip, port, status);

        // 对首次探测为开放的端口执行重试确认
        let mut is_open = matches!(first_connect, Ok(Ok(_)));
        for i in 0..retry_count {
            if !is_open {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            // 重试时重新读取当前超时
            let retry_timeout = Duration::from_millis(timeout_ms.load(Ordering::Relaxed));
            is_open = matches!(
                tokio::time::timeout(retry_timeout, Self::connect_tcp(addr, retry_timeout, optimize_socket)).await,
                Ok(Ok(_))
            );
            info!(
                "scan_tcp_port retry {}/{}: {} {} -> {}",
                i + 1,
                retry_count,
                ip,
                port,
                if is_open { "open" } else { "closed" }
            );
        }

        if !is_open {
            // 未开放：保持首次探测的关闭/过滤状态
            return match first_connect {
                Ok(Err(_)) => PortScanResult {
                    target_ip: target,
                    port,
                    protocol: "TCP".to_string(),
                    status: "关闭".to_string(),
                    service: String::new(),
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms: 0,
                },
                _ => PortScanResult {
                    target_ip: target,
                    port,
                    protocol: "TCP".to_string(),
                    status: "过滤".to_string(),
                    service: String::new(),
                    version: String::new(),
                    banner: String::new(),
                    scan_time_ms: 0,
                },
            };
        }

        // 端口已确认开放，可选抓取 banner
        let (version, banner) = if detect_service {
            // 限制同一目标的并发 banner 抓取，避免占满全部并发
            let _banner_permit = if let Some(sem) = &banner_sem {
                sem.clone().acquire_owned().await.ok()
            } else {
                None
            };
            // banner 单独使用更短的超时（为当前 TCP 超时的一半），防止无响应端口拖慢批次
            let banner_timeout = Duration::from_millis(timeout_ms.load(Ordering::Relaxed)) / 2;
            Self::grab_banner_tcp(addr, banner_timeout).await
        } else {
            (String::new(), String::new())
        };

        // 计算扫描耗时
        let scan_time_ms = scan_start.elapsed().as_millis() as u64;

        PortScanResult {
            target_ip: target,
            port,
            protocol: "TCP".to_string(),
            status: "开放".to_string(),
            service,
            version,
            banner,
            scan_time_ms,
        }
    }

    /// UDP 端口扫描 (异步)
    async fn scan_udp_port(
        target: String,
        ip: IpAddr,
        port: u16,
        timeout_ms: Arc<AtomicU64>,
    ) -> PortScanResult {
        let addr = SocketAddr::new(ip, port);
        let service = get_common_services().get(&port).copied().unwrap_or("unknown").to_string();

        // 读取当前自适应超时
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
        }).await;

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
        }).await;

        match result {
            Ok(Ok(banner)) => {
                // 解析版本信息
                let version = Self::parse_version(&banner);
                (version, banner.lines().take(3).collect::<Vec<_>>().join("\n"))
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
            match res {
                Ok((target, true)) => alive_targets.push(target),
                Ok((_, false)) | Err(_) => {}
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
                    .args(&["-n", "1", "-w", &timeout_ms.to_string(), target])
                    .output()
                    .await
            }
            #[cfg(not(windows))]
            {
                tokio::process::Command::new("ping")
                    .args(&["-c", "1", "-W", "1", target])
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
pub fn get_common_ports() -> Vec<u16> {
    vec![
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
        // UDP 常用端口
        53, 67, 68, 69, 123, 161, 162, 500, 514,
    ]
}

/// 解析端口范围字符串 (如 "1-1000" 或 "22,80,443")
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
pub fn parse_targets(target_str: &str) -> Result<Vec<String>> {
    let mut targets = Vec::new();
    
    for part in target_str.split(',') {
        let part = part.trim();
        
        if part.contains('/') {
            // CIDR 格式 (简化处理)
            let cidr: Vec<&str> = part.split('/').collect();
            if cidr.len() != 2 {
                return Err(anyhow::anyhow!("无效的CIDR格式: {}", part));
            }
            let base_ip: Ipv4Addr = cidr[0].parse()?;
            let mask_bits: u32 = cidr[1].parse()?;
            
            // 计算IP范围
            let base: u32 = u32::from(base_ip);
            let host_bits = 32 - mask_bits;
            let count = 1u32 << host_bits;
            
            for i in 0..count.min(256) { // 限制最多256个
                let ip = Ipv4Addr::from(base + i);
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
            
            for i in start_u32..=end_u32.min(start_u32 + 255) { // 限制最多256个
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