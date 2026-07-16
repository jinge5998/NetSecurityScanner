//! IPC 通信模块
//! 支持命名管道和 TCP 套接字两种通信方式

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*,
    GenericNamespaced, ListenerOptions,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::protocol::{IpcMessage, IpcResponse};
use crate::scanner::{PortScanner, ScanConfig, PortScanResult, ScanProgress};

/// 启动 IPC 服务
pub async fn start_ipc_server(
    mode: &str,
    endpoint: &str,
    concurrency: usize,
    tcp_timeout: u64,
    udp_timeout: u64,
) -> Result<()> {
    let scanner = Arc::new(PortScanner::new(concurrency, tcp_timeout, udp_timeout));

    match mode {
        "pipe" => start_named_pipe_server(endpoint, scanner).await,
        "tcp" => start_tcp_server(endpoint, scanner).await,
        _ => Err(anyhow::anyhow!("不支持的IPC模式: {}", mode)),
    }
}

/// 命名管道服务 (Windows)
async fn start_named_pipe_server(pipe_name: &str, scanner: Arc<PortScanner>) -> Result<()> {
    info!("启动命名管道服务: {}", pipe_name);

    // Windows 命名管道名称格式
    let name_str = format!("{}{}", pipe_name, if cfg!(windows) { "" } else { ".sock" });

    // 创建名称（使用 GenericNamespaced 实现跨平台命名空间映射）
    let name = name_str.to_ns_name::<GenericNamespaced>()
        .context("无法创建命名管道名称")?;

    // 创建监听器
    let listener = ListenerOptions::new().name(name).create_tokio()
        .context("无法创建命名管道监听器")?;

    info!("命名管道服务已启动，等待连接...");

    // 循环处理连接
    loop {
        match listener.accept().await {
            Ok(stream) => {
                info!("新客户端连接");
                let scanner_clone = scanner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client_connection(stream, scanner_clone).await {
                        error!("客户端处理错误: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("接受连接失败: {}", e);
            }
        }
    }
}

/// TCP 套接字服务
async fn start_tcp_server(port_str: &str, scanner: Arc<PortScanner>) -> Result<()> {
    let port: u16 = port_str.parse().context("无效的TCP端口")?;
    let addr = format!("127.0.0.1:{}", port);

    info!("启动TCP服务: {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("TCP服务已启动，等待连接...");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("新客户端连接: {}", addr);
                let scanner_clone = scanner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_client(stream, scanner_clone).await {
                        error!("客户端处理错误: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("接受连接失败: {}", e);
            }
        }
    }
}

/// 向 stream 发送 Error 响应
async fn send_error_response<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    code: i32,
    message: &str,
) -> Result<()> {
    let response = IpcResponse::Error {
        code,
        message: message.to_string(),
    };
    let json = serde_json::to_string(&response)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// 核心扫描执行循环: 给定 stream 和 message,执行扫描并发送结果
/// v1.0.0.9: 修复 biased select! 死锁, 增加诊断日志, 增加心跳保活
async fn run_scan_loop<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    message: IpcMessage,
    scanner: Arc<PortScanner>,
) -> Result<()> {
    let request_id = message.request_id.clone();
    info!(
        "[{}] 收到扫描请求: {} 目标, {} 端口, protocol={}, detect_service={}",
        request_id, message.targets.len(), message.ports.len(),
        message.protocol, message.detect_service.unwrap_or(false)
    );

    // 执行扫描
    let config = ScanConfig {
        targets: message.targets.clone(),
        ports: message.ports.clone(),
        protocol: message.protocol.clone(),
        concurrency: message.concurrency.unwrap_or(1000),
        tcp_timeout_ms: message.tcp_timeout_ms.unwrap_or(200),
        udp_timeout_ms: message.udp_timeout_ms.unwrap_or(500),
        detect_service: message.detect_service.unwrap_or(false),
        include_closed: message.include_closed.unwrap_or(false),
        tcp_concurrency: message.tcp_concurrency,
        udp_concurrency: message.udp_concurrency,
        retry_count: message.retry_count,
        enable_ping_probe: message.enable_ping_probe,
    };

    info!(
        "[{}] 扫描配置: concurrency={}, tcp_timeout={}ms, udp_timeout={}ms",
        request_id, config.concurrency, config.tcp_timeout_ms, config.udp_timeout_ms
    );

    // 创建进度和结果通道 (增大容量以防止背压)
    let (progress_tx, mut progress_rx) = mpsc::channel::<ScanProgress>(256);
    let (result_tx, mut result_tx_recv) = mpsc::channel::<PortScanResult>(20000);

    // 启动扫描任务
    let scan_start = std::time::Instant::now();
    let mut scan_task = tokio::spawn(async move {
        scanner.scan_batch(config, progress_tx, result_tx).await
    });

    let mut scan_done = false;
    let mut scan_result: Result<Vec<PortScanResult>, anyhow::Error> = Ok(Vec::new());
    let mut client_alive = true;
    let mut progress_count: u64 = 0;
    let mut result_count: u64 = 0;
    let mut last_heartbeat = std::time::Instant::now();

    info!("[{}] 进入 select! 循环, 等待扫描结果...", request_id);

    // 实时接收并发送进度和结果
    // 修复: 使用非 biased 模式, 并在 scan_done 且 channel 空时通过超时退出
    while client_alive {
        // 心跳: 每 10 秒发送一次, 防止 C# 端心跳超时
        if last_heartbeat.elapsed() > std::time::Duration::from_secs(10) {
            let heartbeat = IpcResponse::Heartbeat {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                status: "scanning".to_string(),
            };
            if let Ok(json) = serde_json::to_string(&heartbeat) {
                if stream.write_all(json.as_bytes()).await.is_err()
                    || stream.write_all(b"\n").await.is_err()
                    || stream.flush().await.is_err()
                {
                    warn!("[{}] 发送心跳失败 (客户端可能已断开)", request_id);
                    client_alive = false;
                    break;
                }
            }
            last_heartbeat = std::time::Instant::now();
        }

        tokio::select! {
            // 扫描任务完成
            res = &mut scan_task, if !scan_done => {
                match res {
                    Ok(r) => {
                        info!("[{}] 扫描任务正常完成: {} 结果", request_id,
                            r.as_ref().map(|v| v.len()).unwrap_or(0));
                        scan_result = r;
                    }
                    Err(e) => {
                        warn!("[{}] 扫描任务 join 错误: {}", request_id, e);
                        if e.is_panic() {
                            error!("[{}] 扫描任务 panic!", request_id);
                        }
                    }
                }
                scan_done = true;
                info!("[{}] scan_done=true, 继续排空 channel...", request_id);
            }
            // 接收进度
            progress = progress_rx.recv() => {
                match progress {
                    Some(p) => {
                        progress_count += 1;
                        let response = IpcResponse::Progress(p);
                        let json = match serde_json::to_string(&response) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!("[{}] 序列化 progress 失败: {}", request_id, e);
                                continue;
                            }
                        };
                        if stream.write_all(json.as_bytes()).await.is_err()
                            || stream.write_all(b"\n").await.is_err()
                            || stream.flush().await.is_err()
                        {
                            warn!("[{}] 发送 progress 失败 (客户端可能已断开)", request_id);
                            client_alive = false;
                        } else {
                            last_heartbeat = std::time::Instant::now();
                        }
                    }
                    None => {
                        info!("[{}] progress channel 已关闭 (scan_done={})", request_id, scan_done);
                        if scan_done { break; }
                    }
                }
            }
            // 接收结果
            result = result_tx_recv.recv() => {
                match result {
                    Some(r) => {
                        result_count += 1;
                        let response = IpcResponse::Result(r);
                        let json = match serde_json::to_string(&response) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!("[{}] 序列化 result 失败: {}", request_id, e);
                                continue;
                            }
                        };
                        if stream.write_all(json.as_bytes()).await.is_err()
                            || stream.write_all(b"\n").await.is_err()
                            || stream.flush().await.is_err()
                        {
                            warn!("[{}] 发送 result 失败 (客户端可能已断开)", request_id);
                            client_alive = false;
                        } else {
                            last_heartbeat = std::time::Instant::now();
                        }
                    }
                    None => {
                        info!("[{}] result channel 已关闭 (scan_done={})", request_id, scan_done);
                        if scan_done { break; }
                    }
                }
            }
        }
    }

    info!(
        "[{}] select! 循环退出: progress_count={}, result_count={}, client_alive={}, elapsed={}ms",
        request_id, progress_count, result_count, client_alive,
        scan_start.elapsed().as_millis()
    );

    // 确保所有剩余的数据都被发送
    let mut drained_progress = 0u64;
    let mut drained_results = 0u64;
    while let Ok(progress) = progress_rx.try_recv() {
        if !client_alive { break; }
        drained_progress += 1;
        let response = IpcResponse::Progress(progress);
        if let Ok(json) = serde_json::to_string(&response) {
            if stream.write_all(json.as_bytes()).await.is_err() {
                client_alive = false;
                break;
            }
            let _ = stream.write_all(b"\n").await;
            let _ = stream.flush().await;
        }
    }
    while let Ok(result) = result_tx_recv.try_recv() {
        if !client_alive { break; }
        drained_results += 1;
        let response = IpcResponse::Result(result);
        if let Ok(json) = serde_json::to_string(&response) {
            if stream.write_all(json.as_bytes()).await.is_err() {
                client_alive = false;
                break;
            }
            let _ = stream.write_all(b"\n").await;
            let _ = stream.flush().await;
        }
    }
    if drained_progress > 0 || drained_results > 0 {
        info!(
            "[{}] 排空剩余数据: progress={}, results={}",
            request_id, drained_progress, drained_results
        );
    }

    if !client_alive {
        warn!("[{}] 客户端已断开, 跳过发送 Complete 响应", request_id);
        return Ok(());
    }

    // 发送完成响应
    let results = scan_result.unwrap_or_default();
    let open_count = results.iter().filter(|r| r.status == "开放").count();
    let total_scan_time: u64 = results.iter().map(|r| r.scan_time_ms).sum();
    info!(
        "[{}] 发送 Complete: total_results={}, open_ports={}, scan_time_ms={}, wall_elapsed={}ms",
        request_id, results.len(), open_count, total_scan_time,
        scan_start.elapsed().as_millis()
    );
    let complete_response = IpcResponse::Complete {
        total_results: results.len(),
        open_ports: open_count,
        scan_time_ms: total_scan_time,
    };
    let json = serde_json::to_string(&complete_response)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    info!(
        "[{}] 扫描完成: {} 结果, {} 开放端口, 总耗时 {}ms",
        request_id, results.len(), open_count, scan_start.elapsed().as_millis()
    );
    Ok(())
}

/// 处理命名管道客户端连接
async fn handle_client_connection(mut stream: LocalSocketStream, scanner: Arc<PortScanner>) -> Result<()> {
    info!("开始处理客户端连接");
    // 读取请求
    let request_data = {
        let mut reader = BufReader::new(&mut stream);
        match read_request(&mut reader).await {
            Ok(data) => {
                info!("读取到 {} 字节请求", data.len());
                data
            }
            Err(e) => {
                error!("读取请求失败: {}", e);
                return Err(e);
            }
        }
    };

    if request_data.is_empty() {
        return Ok(());
    }

    debug!("收到请求: {} 字节", request_data.len());

    // 解析请求 - 错误时发送 Error 响应, 保持连接
    let message: IpcMessage = match serde_json::from_slice(&request_data) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("[handle_client_connection] 解析请求失败: {}", e);
            warn!("解析请求失败: {}", e);
            send_error_response(&mut stream, 400, &format!("解析请求失败: {}", e)).await?;
            return Ok(());
        }
    };

    // 执行扫描循环
    run_scan_loop(&mut stream, message, scanner).await
}

/// 处理 TCP 客户端连接
async fn handle_tcp_client(mut stream: tokio::net::TcpStream, scanner: Arc<PortScanner>) -> Result<()> {
    // 读取请求
    let request_data = {
        let mut reader = BufReader::new(&mut stream);
        match read_request(&mut reader).await {
            Ok(data) => data,
            Err(e) => {
                return Err(e);
            }
        }
    };

    if request_data.is_empty() {
        return Ok(());
    }

    debug!("收到请求: {} 字节", request_data.len());

    // 解析请求 - 错误时发送 Error 响应, 保持连接
    let message: IpcMessage = match serde_json::from_slice(&request_data) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("[handle_tcp_client] 解析请求失败: {}", e);
            warn!("解析请求失败: {}", e);
            send_error_response(&mut stream, 400, &format!("解析请求失败: {}", e)).await?;
            return Ok(());
        }
    };

    // 执行扫描循环
    run_scan_loop(&mut stream, message, scanner).await
}

/// 从 stream 读取一行 (以 \n 结尾)
async fn read_request<S: AsyncBufReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    stream.read_until(b'\n', &mut buf).await.context("读取请求失败")?;
    Ok(buf)
}