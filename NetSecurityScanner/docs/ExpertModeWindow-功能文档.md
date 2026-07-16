# 专家模式（ExpertModeWindow）功能文档

> 记录日期: 2026-06-21
> 版本: v1.0.0.8
> 代码量: XAML 758 行 + C# 3181 行 = 3939 行

---

## 一、架构总览

```
┌──────────────────────────────────────────────────────────────────┐
│                    ExpertModeWindow (专家模式)                     │
├──────────────────────────────────────────────────────────────────┤
│  6 个 Tab 页 │ 4 种扫描模式 │ 5 种目标类型 │ 4 种端口模式         │
│  8 个 Nmap 模板 │ 6 个预设场景 │ 3 种导出格式 │ Rust 引擎集成      │
├──────────────────────────────────────────────────────────────────┤
│  核心服务: PortScanner / VulnerabilityScanner / RustScannerClient │
│  辅助服务: ScanHistoryService / ScanExportService / JsonDatabaseService │
│  配置管理: ScanProfileManager / ScanRecommendationEngine          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 二、Tab 页布局 (6 个)

| Tab | 名称 | 核心功能 |
|-----|------|----------|
| 🎯 目标配置 | Target Config | 扫描模式、高级参数、目标类型、主机发现、扫描日志 |
| 🔌 端口与服务 | Ports & Services | 端口模式、协议选择、服务检测强度、端口排除 |
| ⚡ 性能调优 | Performance | 并发控制、超时重试、速率限制 |
| 🔒 高级选项 | Advanced | 数据包选项、防火墙/IDS规避、输出控制 |
| 📊 实时结果 | Real-time Results | 进度条、统计面板、端口结果表格、漏洞结果表格 |
| 📋 Nmap模板 | Nmap Templates | 8个Nmap模板 + 6个预设场景 |

---

## 三、扫描模式 (4 种)

| 模式 | 枚举值 | TCP并发 | 超时 | 端口范围 | 适用场景 |
|------|--------|---------|------|----------|----------|
| ⚡ 快速扫描 | Quick | 200 | 200ms | Top 1000 | 快速资产发现 |
| 📋 标准扫描 | Standard | 50 | 500ms | Top 1000 | 日常安全巡检 |
| 🔬 深度扫描 | Deep | 20 | 2000ms | 1-65535 | 全量安全审计 |
| 🔧 自定义 | Custom | 可调 | 可调 | 可调 | 高级安全测试 |

### 推荐引擎（RecommendationEngine）

- 根据目标数量自动推荐最优扫描模式
- 点击"🎯 推荐模式"按钮自动应用
- 显示推荐理由（如："目标数量较多建议使用快速模式"）

---

## 四、目标类型 (5 种)

| 类型 | 控件 | 输入格式 | 示例 |
|------|------|----------|------|
| 单个IP/域名 | SingleIpRadio | 单个地址 | `192.168.1.1` / `www.example.com` |
| IP段范围 | IpRangeRadio | 起始-结束 | `192.168.1.1-192.168.1.254` |
| CIDR网段 | CidrRadio | IP/前缀 | `192.168.1.0/24` |
| 文件列表 | FileRadio | 每行一个IP | 导入 .txt/.csv 文件 |
| 正则模式 | RegexRadio | 正则表达式 | `192\.168\.1\.[0-9]+` |

### 高级目标选项

- 反向DNS解析
- 主机发现(先Ping再扫描)
- 排除主机列表（逗号分隔，支持CIDR）

---

## 五、端口与服务配置

### 端口模式 (4 种)

| 模式 | 端口范围 | 说明 |
|------|----------|------|
| 常用端口 | Top 1000 | Nmap 常用端口排名 |
| 敏感端口 | Top 100 | 高危服务端口 |
| 全部端口 | 1-65535 | 全量扫描 |
| 自定义端口 | 用户指定 | 支持范围格式 `22,80,443,8000-9000` |

### 协议与检测

| 选项 | 说明 |
|------|------|
| TCP扫描 | 标准TCP连接扫描 |
| UDP扫描 | UDP数据包扫描 |
| SYN半开扫描 | 隐蔽扫描，不建立完整连接 |
| 服务版本检测 | 识别运行服务及版本号 |
| 操作系统识别 | 操作系统指纹识别 |
| NSE脚本扫描 | Nmap脚本引擎安全检测 |

### 服务检测强度 (5 级)

| 级别 | 说明 |
|------|------|
| 0 - 仅常用端口 | 最少探测 |
| 1 - 标准检测 | 常规服务识别 |
| 2 - 增强检测 | 更详细的服务信息 |
| 3 - 全部检测 | 完整服务探测 |
| 4 - 暴力检测 | 最激进检测模式 |

---

## 六、性能调优

### 并发控制

| 参数 | 范围 | 默认值 | 说明 |
|------|------|--------|------|
| TCP最大并发 | 1-500 | 50 | 同时进行的TCP连接数 |
| UDP最大并发 | 1-200 | 20 | 同时进行的UDP探测数 |

### 超时与重试

| 参数 | 范围 | 默认值 | 说明 |
|------|------|--------|------|
| TCP超时 | 100-5000ms | 500ms | TCP连接超时 |
| UDP超时 | 500-10000ms | 1000ms | UDP响应等待 |
| 重试次数 | 0-5 | 1 | 失败重试次数 |

### 速率限制

- 启用速率限制：控制发包速率，避免触发IDS
- 数据包速率：10-10000 pps（包/秒）

---

## 七、高级选项

### 数据包选项

| 选项 | 说明 |
|------|------|
| 源端口 | 指定源端口（0=随机） |
| MTU | 最大传输单元，用于数据包分片 |
| 数据包分片 | 绕过简单IDS检测 |
| 错误校验和 | 使用错误校验和绕过部分防火墙 |
| Stealth模式 | 低速率隐蔽扫描 |
| 随机化目标顺序 | 打乱扫描顺序降低检测风险 |

### 防火墙/IDS规避

| 选项 | 说明 |
|------|------|
| 诱饵扫描 | 伪装多个源IP，隐藏真实扫描源 |
| Idle僵尸扫描 | 完全隐蔽扫描，使用中间主机 |
| 源路由 | 使用松散/严格源路由 |

### 输出控制

| 选项 | 说明 |
|------|------|
| 日志级别 | 安静/标准/详细/调试 |
| 输出格式 | JSON / HTML / CSV |
| 保存输出到文件 | 自动保存扫描结果 |
| 输出目录 | 自定义输出路径 |

---

## 八、实时结果展示

### 扫描进度

- 进度条 + 百分比文本
- 扫描引擎状态显示（C# / Rust）
- Rust 引擎状态（就绪/运行/不可用）

### 统计面板 (4 项)

| 统计项 | 说明 |
|--------|------|
| 总目标数 | 解析出的目标主机数量 |
| 已扫描 | 已完成扫描的目标数 |
| 开放端口 | 发现的开放端口总数 |
| 发现漏洞 | 检测到的漏洞总数 |

### 端口扫描结果表格

| 列名 | 说明 |
|------|------|
| 目标IP | 扫描目标地址 |
| 端口 | 端口号 |
| 状态 | 开放/关闭/过滤 |
| 服务 | 服务名称 |
| 版本 | 服务版本号 |
| 响应时间(ms) | 扫描响应时间 |

**右键菜单**: 复制选中行 / 删除选中行 / 导出CSV / 导出JSON / 按端口排序 / 筛选开放端口

### 漏洞扫描结果表格

| 列名 | 说明 |
|------|------|
| 序号 | 漏洞编号 |
| 漏洞名称 | 漏洞标题 |
| CVE编号 | CVE标识 |
| 风险等级 | Critical/High/Medium/Low |
| 端口 | 关联端口 |
| 服务 | 关联服务 |
| 目标 | 目标主机 |
| 描述 | 漏洞详细描述 |

**右键菜单**: 复制选中行 / 按风险等级排序 / 筛选高危 / 筛选中危

---

## 九、Nmap 模板 (8 个)

| 模板 | 按钮 | 核心配置 |
|------|------|----------|
| 快速扫描 (-F) | ⚡ | 常用端口、200并发、200ms超时、不重试 |
| 隐蔽扫描 (-sS) | 🥷 | SYN半开、10并发、限速100pps、Stealth模式 |
| 激进扫描 (-A) | 💥 | 全端口、TCP+UDP、服务+OS+脚本、30并发 |
| Ping扫描 (-sn) | 📡 | 仅主机发现、不扫描端口 |
| 全端口扫描 (-p-) | 🔍 | 1-65535、SYN半开、20并发 |
| 版本检测 (-sV) |  | 常用端口、增强服务版本检测 |
| 系统检测 (-O) | 🖥️ | SYN半开、服务+OS识别 |
| 默认扫描 |  | 常用端口、TCP、服务版本检测 |

---

## 十、预设场景 (6 个)

| 场景 | 按钮 | 目标端口 | 特点 |
|------|------|----------|------|
| Web服务器检测 | 🌐 | 80/443/8080/8443等 | 增强服务检测 |
| 数据库安全检测 | ️ | MySQL/Redis/MongoDB等 | 暴力检测强度 |
| WiFi路由器检测 | 📶 | 管理端口 | TCP+UDP、服务+OS |
| 合规性检查 | ✅ | 全端口 | 全协议、详细检测、HTML报告 |
| 漏洞专项检测 |  | 全部端口 | 完整检测、NSE脚本 |
| 隐蔽审计 | 👻 | 敏感端口 | SYN半开、5并发、限速50pps |

---

## 十一、Rust 高性能扫描引擎

### 初始化流程

```
ExpertModeWindow 构造
    → InitializeRustScanner()
        → 查找 Rust 可执行文件 (rust-scanner-service.exe)
        → 创建 RustScannerClient
        → 注册事件: OnLog / OnProgressChanged / OnResultReceived / OnScanComplete
        → 更新引擎状态显示
```

### 扫描执行流程

```
StartExpertScanButton_Click
    → CollectConfig()
    → ExecuteExpertScanAsync()
        → 解析目标 (ResolveTargets)
        → 解析端口 (ResolvePorts)
        → 尝试启动 Rust 服务
            ├─ 成功 → ExecuteRustScanAsync()  (5-10x 性能提升)
            └─ 失败 → ExecuteNativeScanAsync() (C# 内置扫描器)
        → 保存扫描历史
```

### Rust 可执行文件查找路径

| 优先级 | 路径 |
|--------|------|
| 1 | `{BaseDirectory}\rust-scanner-service.exe` |
| 2 | `{ProjectRoot}\src\NetSecurityScanner.Desktop\bin\Debug\net6.0-windows\rust-scanner-service.exe` |
| 3 | `{ProjectRoot}\src\NetSecurityScanner.Desktop\bin\Release\net6.0-windows\rust-scanner-service.exe` |
| 4 | `{ProjectRoot}\src\NetSecurityScanner.Desktop\RustEngine\target\release\rust-scanner-service.exe` |

---

## 十二、导出功能

### 支持的导出格式

| 导出方式 | 格式 | 触发方式 |
|----------|------|----------|
| HTML报告 | .html | 实时结果Tab → 📄 导出HTML报告 |
| CSV导出 | .csv | 实时结果Tab → 📊 导出CSV |
| JSON导出 | .json | 实时结果Tab → 💾 导出JSON |
| Nmap命令 | .bat/.sh/.txt | 底部按钮 → 📋 导出Nmap命令 |
| 端口结果CSV | .csv | 端口表格右键菜单 |
| 端口结果JSON | .json | 端口表格右键菜单 |

### Nmap 命令生成器

- 自动将当前配置翻译为等效 Nmap 命令行
- 支持参数: `-sS`, `-sU`, `-sV`, `-O`, `-sC`, `-p-`, `--max-rate`, `-T2`, `-f`, `-D`, `--randomize-hosts` 等
- 一键复制到剪贴板
- 支持保存为 .bat / .sh 脚本

---

## 十三、配置管理

### 预设加载/保存

| 功能 | 按钮 | 说明 |
|------|------|------|
| 加载预设 | 📂 加载预设 | 从 JSON 文件加载扫描配置 |
| 保存预设 | 💾 保存预设 | 将当前配置保存为 JSON 文件 |
| 验证配置 | ✅ 验证配置 | 检查配置有效性（目标格式、端口范围、参数冲突） |

### 配置验证规则

| 检查项 | 类型 |
|--------|------|
| 目标为空 | ❌ 错误 |
| IP格式无效 | ⚠️ 警告 |
| IP段格式错误 | ❌ 错误 |
| CIDR格式错误 | ❌ 错误 |
| 自定义端口为空 | ❌ 错误 |
| 端口格式错误 | ❌ 错误 |
| TCP并发 > 200 | ⚠️ 警告 |
| TCP超时 < 100ms | ⚠️ 警告 |
| Stealth模式 + 高并发 | ⚠️ 警告 |
| 速率限制 > 5000pps | ⚠️ 警告 |

### 扫描计划预览

底部栏实时显示：
- 🎯 目标数量
- 🔌 端口数量
- ⏱️ 预计耗时
- 📊 总扫描数

---

## 十四、UI 性能优化

### 节流与批处理策略

| 优化项 | 机制 | 间隔 |
|--------|------|------|
| 日志缓冲 | `ConcurrentQueue<string>` + 定时刷新 | 200ms |
| 数据刷新 | 脏标记 `_portDataDirty` / `_vulnDataDirty` | 250ms |
| 进度更新 | 时间戳比较 `_lastProgressUpdate` | 150ms |
| 定时器 | `DispatcherTimer` (Background 优先级) | — |

### 生命周期管理

```
Loaded → 初始化控件 → 加载默认配置 → 加载上次配置 → 更新摘要
Closed → 停止定时器 → 停止Rust服务 → 释放资源 → 取消令牌
```

---

## 十五、核心服务依赖

| 服务 | 命名空间 | 职责 |
|------|----------|------|
| `PortScanner` | NetSecurityScanner.Services | TCP/UDP 端口扫描 |
| `VulnerabilityScanner` | NetSecurityScanner.Services | 漏洞检测 |
| `RustScannerClient` | NetSecurityScanner.Core.Services | Rust 高性能扫描客户端 |
| `ScanHistoryService` | NetSecurityScanner.Core.Services | 扫描历史持久化 |
| `ScanExportService` | NetSecurityScanner.Core.Services | 结果导出(HTML/CSV/JSON) |
| `JsonDatabaseService` | NetSecurityScanner.Services | JSON 数据库读写 |
| `ScanProfileManager` | NetSecurityScanner.Core.Models | 扫描配置持久化 |
| `ScanRecommendationEngine` | NetSecurityScanner.Core.Models | 智能推荐扫描模式 |

---

## 十六、模型定义

### ExpertScanConfiguration

```csharp
class ExpertScanConfiguration
{
    ScanProfile Profile;       // 扫描模式
    string TargetValue;        // 目标输入
    string TargetType;         // 目标类型
    string PortMode;           // 端口模式
    string CustomPorts;        // 自定义端口
    bool TcpScan, UdpScan, SynScan;           // 协议
    bool ServiceDetection, OsDetection, ScriptScan; // 检测选项
    int TcpConcurrency, UdpConcurrency;       // 并发
    int TcpTimeout, UdpTimeout, RetryCount;    // 超时/重试
    bool RateLimit; int PacketRate;            // 速率限制
    bool StealthMode, Randomize, FragmentPackets;  // 隐蔽
    bool DecoyScan; string DecoyIps;           // 诱饵
    bool IdleScan; string ZombieHost;          // 僵尸扫描
    bool SourceRouting;                        // 源路由
    string SourcePort; int Mtu;                // 数据包
    bool BadChecksum;                          // 校验和
    int Verbosity;                             // 日志级别
    bool SaveOutput; string OutputDir;         // 输出
    bool OutputJson, OutputHtml, OutputCsv;    // 输出格式
    bool ReverseDns, HostDiscovery;            // 高级目标
    string ExcludeHosts, ExcludePorts;         // 排除
    int ServiceIntensity;                      // 服务检测强度
    DateTime StartTime, EndTime;               // 时间
    TimeSpan Duration;                         // 耗时
}
```

### ScanProfileConfig

```csharp
class ScanProfileConfig
{
    ScanProfile Profile;
    int TcpConcurrency, UdpConcurrency;
    int TimeoutMs, RetryCount;
    bool EnablePingProbe, EnableServiceDetection;
    string PortRange;
}
```

---

## 十七、关键方法索引

| 方法 | 行号 | 功能 |
|------|------|------|
| `InitializeRustScanner` | ~130 | Rust 引擎初始化 |
| `LoadProfileConfig` | ~258 | 加载上次扫描配置 |
| `ScanProfileComboBox_SelectionChanged` | ~440 | 扫描模式切换 |
| `RecommendProfileButton_Click` | ~460 | 智能推荐模式 |
| `CollectConfig` | ~950 | 收集界面配置 |
| `StartExpertScanButton_Click` | 1123 | 启动扫描入口 |
| `ExecuteExpertScanAsync` | 1200 | 核心扫描执行 |
| `ExecuteRustScanAsync` | ~1400 | Rust 扫描执行 |
| `ExecuteNativeScanAsync` | ~1700 | C# 原生扫描 |
| `ResolveTargets` | ~1800 | 目标解析 |
| `ResolvePorts` | ~1900 | 端口解析 |
| `NmapFastBtn_Click` 等 8个 | 2015-2170 | Nmap 模板 |
| `PresetWebServerBtn_Click` 等 6个 | 2176-2310 | 预设场景 |
| `ExportNmapButton_Click` | 2314 | 导出 Nmap 命令 |
| `GenerateNmapCommand` | 2350 | Nmap 命令生成 |
| `ValidateConfigButton_Click` | 2430 | 配置验证 |
| `UpdateScanPlanPreview` | 2539 | 扫描计划预览 |
| `ExportHtmlButton_Click` | 2598 | 导出 HTML |
| `ExportCsvButton_Click` | 2633 | 导出 CSV |
| `ExportJsonButton_Click` | 2641 | 导出 JSON |
| `AppendLog` | 2849 | 日志追加 |
| `FlushLogBuffer` | 2875 | 日志缓冲刷新 |
| `AddPortResultSafe` | 2913 | 线程安全添加端口结果 |
| `UpdateProgressSafe` | 2955 | 线程安全更新进度 |
| `SortByPort_Click` | 3067 | 按端口排序 |
| `FilterOpenPorts_Click` | 3076 | 筛选开放端口 |
| `SortByRiskLevel_Click` | 3101 | 按风险等级排序 |
| `FilterHighRisk_Click` | 3111 | 筛选高危漏洞 |
| `FilterMediumRisk_Click` | 3119 | 筛选中危漏洞 |

---

## 十八、v1.0.0.9 待优化项

| 任务ID | 改进项 | 优先级 | 说明 |
|--------|--------|--------|------|
| EXP-001 | 扫描历史回放 | 🟠 Medium | 支持查看历史扫描结果和对比 |
| EXP-002 | 批量扫描队列 | 🔴 High | 多目标排队扫描、进度总览 |
| EXP-003 | 自定义 NSE 脚本 | 🟡 Low | 支持用户上传自定义 NSE 脚本 |
| EXP-004 | 扫描报告对比 | 🟡 Low | 两次扫描结果差异对比 |
| EXP-005 | WebSocket 实时推送 | 🟠 Medium | 扫描进度通过 WebSocket 推送前端 |
| EXP-006 | 定时扫描任务 | 🔴 High | 支持 Cron 表达式定时扫描 |
| EXP-007 | 扫描结果通知 | 🟠 Medium | 邮件/钉钉/企业微信通知 |
| EXP-008 | 并发数自适应 | 🟡 Low | 根据网络延迟自动调整并发数 |

---

将此文件保存至 `docs/ExpertModeWindow-功能文档.md`，v1.0.0.9 可据此继续开发。