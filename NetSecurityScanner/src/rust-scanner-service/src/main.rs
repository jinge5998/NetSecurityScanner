//! 高性能网络安全扫描服务 v1.0.0.8
//! 使用 Rust + Tokio 实现异步并发端口扫描

mod scanner;
mod ipc;
mod protocol;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// 命令行参数
#[derive(Parser, Debug)]
#[command(name = "rust-scanner-service")]
#[command(about = "高性能网络安全扫描服务", long_about = None)]
struct Args {
    /// IPC 通信模式: pipe (命名管道) 或 tcp (TCP套接字)
    #[arg(short, long, default_value = "pipe")]
    mode: String,

    /// 命名管道名称或 TCP 端口
    #[arg(short, long, default_value = "NetSecurityScannerIPC")]
    endpoint: String,

    /// 最大并发连接数
    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

    /// TCP 超时时间(毫秒)
    #[arg(short, long, default_value = "200")]
    tcp_timeout: u64,

    /// UDP 超时时间(毫秒)
    #[arg(short, long, default_value = "500")]
    udp_timeout: u64,

    /// 日志级别
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 初始化日志
    let level = match args.log_level.as_str() {
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("🚀 Rust 高性能扫描服务 v1.0.0.8 启动");
    info!("并发数: {}, TCP超时: {}ms, UDP超时: {}ms", args.concurrency, args.tcp_timeout, args.udp_timeout);

    // 启动 IPC 服务
    tokio::runtime::Runtime::new()?.block_on(async {
        ipc::start_ipc_server(&args.mode, &args.endpoint, args.concurrency, args.tcp_timeout, args.udp_timeout).await
    })
}