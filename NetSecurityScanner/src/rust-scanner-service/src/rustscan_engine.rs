//! RustScan 引擎封装
//!
//! 将 RustScan（https://github.com/bee-san/RustScan，源码见 `vendor/RustScan-2.4.1`）
//! 的批量 TCP 端口发现能力集成进本服务的 IPC 框架：
//!
//! * 对外仍由 [`crate::scanner::PortScanner`] 暴露 `scan_batch` 接口，C# 端无需改动；
//! * 本模块只负责“端口发现”，Banner 抓取、UDP 扫描、进度上报仍由 `scanner` 模块完成；
//! * RustScan 内部基于 async-std，为避免与 tokio 运行时混用，扫描在其独立的阻塞线程中执行。

use anyhow::Result;
use rustscan::input::ScanOrder;
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info};

/// 进度上报的分块数：端口被切成若干块依次交给 RustScan 扫描，
/// 每完成一块上报一次进度，避免长扫描期间 UI 进度条长时间静止。
const PROGRESS_CHUNKS: usize = 10;

/// RustScan 引擎配置与调用封装
#[derive(Debug, Clone)]
pub struct RustScanEngine {
    /// 单批并发扫描的端口数（映射到 RustScan 的 batch_size）
    batch_size: u16,
    /// 单个端口的连接超时
    timeout: Duration,
    /// 每个端口的重试次数（至少 1）
    tries: u8,
}

impl RustScanEngine {
    /// 创建引擎实例
    ///
    /// * `concurrency`：并发端口数，会映射为 RustScan 的 batch_size（上限 65535）
    /// * `timeout_ms`：TCP 连接超时（毫秒），最小 1ms
    /// * `tries`：重试次数，至少 1 次（RustScan 内部使用 NonZeroU8）
    pub fn new(concurrency: usize, timeout_ms: u64, tries: u32) -> Self {
        Self {
            batch_size: concurrency.clamp(1, u16::MAX as usize) as u16,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            tries: tries.clamp(1, u8::MAX as u32) as u8,
        }
    }

    /// 当前使用的批量大小
    pub fn batch_size(&self) -> u16 {
        self.batch_size
    }

    /// 扫描单个目标上的指定端口，返回**开放端口**列表（升序、已去重）
    ///
    /// `on_progress` 会在每完成一个分块时被调用，参数为
    /// `(本目标已扫描端口数, 本目标已发现开放端口数)`。
    /// 回调在异步任务中同步执行，内部应使用非阻塞的 `try_send`。
    pub async fn scan_open_tcp_ports<F>(
        &self,
        target: IpAddr,
        ports: &[u16],
        mut on_progress: F,
    ) -> Result<Vec<u16>>
    where
        F: FnMut(usize, usize),
    {
        if ports.is_empty() {
            return Ok(Vec::new());
        }

        let total = ports.len();
        // 分块大小：既要保证每次进度跨度不至于太粗（约 10 块），
        // 又不能小于 batch_size，否则并发度会被分块大小限制。
        let chunk_size = (total / PROGRESS_CHUNKS)
            .max(self.batch_size as usize)
            .max(1);

        let mut open_ports: Vec<u16> = Vec::new();
        let mut scanned = 0usize;

        debug!(
            "RustScan 分块扫描: target={}, ports={}, chunk_size={}, batch_size={}",
            target, total, chunk_size, self.batch_size
        );

        for chunk in ports.chunks(chunk_size) {
            let mut found = self.scan_chunk(target, chunk).await?;
            open_ports.append(&mut found);
            scanned += chunk.len();
            on_progress(scanned, open_ports.len());
        }

        open_ports.sort_unstable();
        open_ports.dedup();

        info!(
            "RustScan 引擎完成: target={}, 扫描端口={}, 开放={}",
            target,
            total,
            open_ports.len()
        );
        Ok(open_ports)
    }

    /// 调用 RustScan 扫描一个分块，返回该分块内的开放端口
    async fn scan_chunk(&self, target: IpAddr, chunk: &[u16]) -> Result<Vec<u16>> {
        let ips = [target];
        let ports: Vec<u16> = chunk.to_vec();
        let batch_size = self.batch_size;
        let timeout = self.timeout;
        let tries = self.tries;

        let sockets = tokio::task::spawn_blocking(move || {
            let strategy = PortStrategy::pick(&None, Some(ports), ScanOrder::Serial);
            let scanner = Scanner::new(
                &ips,
                batch_size,
                timeout,
                tries,
                true, // greppable：不向控制台打印，避免污染 IPC 输出
                strategy,
                true,       // accessible：非 greppable 模式下的兼容输出
                Vec::new(), // 不排除任何端口
                false,      // 仅做 TCP 端口发现，UDP 由 scanner 模块处理
            );
            async_std::task::block_on(scanner.run())
        })
        .await;

        let sockets = match sockets {
            Ok(v) => v,
            Err(join_err) => return Err(Self::map_join_error(join_err, batch_size)),
        };

        Ok(sockets.into_iter().map(|socket| socket.port()).collect())
    }

    /// 把 `spawn_blocking` 的 `JoinError` 转换成带可操作建议的错误
    ///
    /// RustScan 在检测到 "too many open files"（EMFILE，句柄耗尽）时会通过
    /// `assert!` 直接 panic。`spawn_blocking` 会把该 panic 捕获为 `JoinError`，
    /// 若原样上报，调用方只能看到 "线程异常退出"，无法得知真正原因是并发过高。
    /// 这里提取 panic 载荷并给出明确的降低并发建议。
    fn map_join_error(join_err: tokio::task::JoinError, batch_size: u16) -> anyhow::Error {
        let detail = if join_err.is_panic() {
            let payload = join_err.into_panic();
            if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "未知 panic 载荷".to_string()
            }
        } else {
            join_err.to_string()
        };

        if is_handle_exhausted(&detail) {
            anyhow::anyhow!(
                "RustScan 引擎文件句柄耗尽（EMFILE）：请降低并发数（当前 batch_size={}，建议 ≤1000）。原始错误: {}",
                batch_size,
                detail
            )
        } else {
            anyhow::anyhow!("RustScan 扫描线程异常退出: {}", detail)
        }
    }
}

/// 判断错误信息是否属于"文件句柄耗尽"（EMFILE）
///
/// 该判定与 RustScan 内部 `assert!` 的匹配条件保持一致（小写包含匹配），
/// 保证我们在同一场景下给出可操作的建议。
fn is_handle_exhausted(detail: &str) -> bool {
    detail.to_ascii_lowercase().contains("too many open files")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_handle_exhausted_matches_rustscan_assert_message() {
        // 与 vendor/RustScan-2.4.1/src/scanner/mod.rs 中 assert! 的触发文本一致
        assert!(is_handle_exhausted(
            "Too many open files. Please reduce batch size."
        ));
    }

    #[test]
    fn is_handle_exhausted_is_case_insensitive() {
        assert!(is_handle_exhausted("TOO MANY OPEN FILES"));
    }

    #[test]
    fn is_handle_exhausted_rejects_unrelated_errors() {
        assert!(!is_handle_exhausted("Connection refused"));
        assert!(!is_handle_exhausted(""));
    }

    #[test]
    fn engine_clamps_invalid_parameters() {
        // 并发为 0 时 batch_size 至少为 1，超时与重试也各自兜底，避免下游 NonZeroU8 构造失败
        let engine = RustScanEngine::new(0, 0, 0);
        assert_eq!(engine.batch_size(), 1);

        // 并发超过 u16 上限时截断，避免 as u16 回绕成 0
        let engine = RustScanEngine::new(usize::MAX, 200, 1);
        assert_eq!(engine.batch_size(), u16::MAX);

        // 重试次数超过 u8 上限时截断，避免回绕
        let engine = RustScanEngine::new(1000, 200, u32::MAX);
        assert_eq!(engine.tries, u8::MAX);
    }

    #[test]
    fn engine_keeps_valid_parameters() {
        let engine = RustScanEngine::new(1000, 300, 2);
        assert_eq!(engine.batch_size(), 1000);
        assert_eq!(engine.timeout, Duration::from_millis(300));
        assert_eq!(engine.tries, 2);
    }
}
