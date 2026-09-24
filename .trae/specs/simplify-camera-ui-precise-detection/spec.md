# 简化摄像头扫描 UI + 提升检测准确度 Spec

## Why
当前 `CameraSecurityScannerWindow` 顶部 RiskDashboard（5 张风险等级卡片 + VendorBarChart + LineChart + RiskGauge）占据约 200px 高度，分散了用户对核心扫描结果（IP 列表）的注意力。同时，现网摄像头识别存在两类问题：
- **误报**：基于端口（如 554/80/8080）的扫描把路由器、NAS、普通 Web 服务器都标记为摄像头
- **漏报**：对海康/大华/宇视/萤石/雄迈/天地伟业等非标准端口（如 8000/37777/34567/34599/6036）覆盖不全；对小厂/私有协议摄像头无指纹规则

用户希望**先把"扫描到摄像头"这一件事做精**，再考虑其他增强。

## What Changes
- **简化 UI**：移除顶部 RiskDashboard（5 张风险卡 + VendorBarChart + LineChart + RiskGauge），主窗口只保留：标题、目标输入、扫描控制、结果列表
- **检测升级**：扩展 `CameraDiscoveryService` 与 `CameraFingerprintService` 的检测维度，提高识别准确率
  - 增加厂商默认端口探测（端口优先 → 厂商指纹 → HTTP 指纹 → ONVIF 多级验证）
  - 引入"摄像头特征关键词白名单" + "反例黑名单"（路由器/打印机/NAS 等）
  - 引入 ONVIF `GetCapabilities`/`GetSystemDateAndTime` 二次确认
- **服务层**：将"摄像头判定"封装成 `CameraVerifier`，对外暴露 `VerificationResult { IsCamera, Confidence, Vendor, Method }`
- **结果展示**：在结果列表中新增"判定依据"列（首次识别使用什么方法找到的）
- **不影响**：标签、弱口令、趋势等已完成的 v4 功能保留在代码中，但默认入口从主窗口隐藏（仍可通过 `ShowAdvancedTools` 开关调用）

## Impact
- Affected specs: enhance-camera-scan-and-plugin-v2（v4 中扫描统计图表 UI 部分标记为 deprecated，但服务层保留）
- Affected code:
  - `NetSecurityScanner.Desktop/Views/Views/CameraSecurityScannerWindow.xaml(.cs)`（移除 Grid.Row="0"/"1" 的 RiskDashboard 区，标题上移）
  - `NetSecurityScanner.Core/Services/CameraVerifier.cs`（新）
  - `NetSecurityScanner.Core/Services/CameraDiscoveryService.cs`（扩展厂商端口列表）
  - `NetSecurityScanner.Core/Services/CameraFingerprintService.cs`（增加反例过滤）
  - `NetSecurityScanner.Core/Data/CameraFingerprintDB.json`（补充小厂指纹）
  - `NetSecurityScanner.Core/Models/CameraScanResult.cs`（新增 VerificationMethod 字段）

## ADDED Requirements

### Requirement: 简化主窗口 UI
主窗口移除顶部 RiskDashboard，整体高度从 ~880px 缩减到 ~680px。结果表格获得更多垂直空间。
#### Scenario: 打开摄像头扫描窗口
- **WHEN** 用户从主菜单进入"摄像头安全扫描"
- **THEN** 窗口仅显示：标题栏 → 目标输入区 → 扫描控制/选项 → 实时日志 → 结果表格 + 详情

### Requirement: 精准摄像头判定
引入 `CameraVerifier` 服务，按"端口 → 厂商关键字 → HTTP/RTSP 指纹 → ONVIF 协议"逐级验证，输出置信度（0-1）。
#### Scenario: 扫描局域网 C 段
- **WHEN** 扫描 192.168.1.0/24
- **THEN** 真正摄像头（Hikvision/Dahua/Axis/TP-Link Tapo 等）的识别率 ≥ 95%；误报率（普通 Web 服务器被误判为摄像头）< 5%

### Requirement: 反例过滤
对探测到的服务，先做反例匹配：路由/打印机/NAS/Windows 主机响应 → 不标记为摄像头。
#### Scenario: 80 端口返回路由器管理页
- **WHEN** 设备 HTTP 响应包含 "D-Link" / "TP-LINK Router" / "Synology" / "QNAP" / "HP Printer"
- **THEN** 结果标记为"非摄像头"，不出现在摄像头结果列表

### Requirement: 厂商默认端口表
内置 ≥ 10 个国内主流厂商的默认管理端口（含 RTSP/HTTP/ONVIF）。
#### Scenario: 扫描海康设备
- **WHEN** 探测 8000/554/80/8080 端口
- **THEN** 同时尝试 8000（Hikvision HTTP）和 554（RTSP），避免漏检非标准端口设备

### Requirement: 保留高级功能入口
标签管理、弱口令、趋势窗口功能在代码中保留，主窗口提供一个折叠的"高级"按钮可调出。
#### Scenario: 点击"高级"
- **WHEN** 用户点击工具栏"高级"按钮
- **THEN** 弹出含"标签管理/弱口令编辑/历史趋势"的菜单

## MODIFIED Requirements
### Requirement: 顶部 RiskDashboard（来自 v4-T1）
**变更**：UI 移除该区；服务层 `CameraScanStatisticsService` 保留以备复用。
**迁移**：未来如需恢复 Dashboard，可在高级设置中提供"显示统计图表"开关。

## REMOVED Requirements
无

## Anti-Goals（明确不做）
- 不修改 v4 已完成的标签、弱口令、趋势服务代码
- 不引入新的 UI 库（LiveCharts/OxyPlot 等），保持 WPF 原生
- 不重写端口扫描核心（沿用 `PortScanner` + `CameraScannerService`）
- 不在本次改动 ONVIF 完整设备控制功能（PTZ/视频流）
