//! IPC 通信协议定义 v1.0.2.1

use crate::scanner::{PortScanResult, ScanProgress};
use serde::{Deserialize, Serialize};

/// IPC 请求消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    /// 唯一请求ID
    pub request_id: String,
    /// 消息类型
    pub message_type: String,
    /// 目标IP列表
    pub targets: Vec<String>,
    /// 端口列表
    pub ports: Vec<u16>,
    /// 扫描协议 (tcp/udp/both)
    pub protocol: String,
    /// 扫描模式: connect(TCP连接) / syn(SYN扫描) / udp
    pub scan_mode: Option<String>,
    /// 最大并发数
    pub concurrency: Option<usize>,
    /// TCP超时(ms)
    pub tcp_timeout_ms: Option<u64>,
    /// UDP超时(ms)
    pub udp_timeout_ms: Option<u64>,
    /// 是否检测服务版本
    pub detect_service: Option<bool>,
    /// 是否包含关闭端口
    pub include_closed: Option<bool>,
    /// 速率限制 (包/秒, 0=不限速)
    pub rate_limit: Option<u32>,
    /// 是否随机化扫描顺序
    pub randomize: Option<bool>,
    /// TCP 并发数（覆盖默认值）
    pub tcp_concurrency: Option<u32>,
    /// UDP 并发数（覆盖默认值）
    pub udp_concurrency: Option<u32>,
    /// 开放端口重试确认次数
    pub retry_count: Option<u32>,
    /// 扫描前是否执行 Ping 存活探测
    pub enable_ping_probe: Option<bool>,
}

/// IPC 响应消息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IpcResponse {
    /// 进度报告
    Progress(ScanProgress),
    /// 单个扫描结果
    Result(PortScanResult),
    /// 扫描完成
    Complete {
        total_results: usize,
        open_ports: usize,
        scan_time_ms: u64,
    },
    /// 错误响应
    Error { code: i32, message: String },
    /// 心跳响应
    Heartbeat { timestamp: i64, status: String },
}

/// 创建默认扫描请求
pub fn create_scan_request(targets: Vec<String>, ports: Vec<u16>, protocol: String) -> IpcMessage {
    IpcMessage {
        request_id: uuid::Uuid::new_v4().to_string(),
        message_type: "scan".to_string(),
        targets,
        ports,
        protocol,
        scan_mode: Some("connect".to_string()),
        concurrency: Some(1000),
        tcp_timeout_ms: Some(200),
        udp_timeout_ms: Some(500),
        detect_service: Some(false),
        include_closed: Some(false),
        rate_limit: Some(0),
        randomize: Some(false),
        tcp_concurrency: None,
        udp_concurrency: None,
        retry_count: None,
        enable_ping_probe: None,
    }
}

// 简化 UUID 生成 (避免额外依赖)
mod uuid {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Self
        }

        pub fn to_string(&self) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            format!("{:016x}", now)
        }
    }
}
