# Tasks - 简化摄像头扫描 UI + 提升检测准确度

- [ ] T1: 简化主窗口 UI（移除 RiskDashboard）
  - [ ] T1.1: 删除 `CameraSecurityScannerWindow.xaml` 中 Grid.Row="0" 的 5 张风险等级卡片和 Grid.Row="1" 的 VendorBarChart/LineChart/RiskGauge
  - [ ] T1.2: 调整 Grid Row 索引（标题、目标输入、扫描选项、日志、结果依次上移）
  - [ ] T1.3: 移除 `UpdateDashboard` 调用及 `CameraScanStatisticsService` 引用（保留类供未来复用）
  - [ ] T1.4: 在工具栏新增"高级"按钮，下拉含"标签管理/弱口令/历史趋势"入口
  - [x] T1.5: 验证窗口高度从 ~880px 缩减到 ~680px，结果表格获得更多垂直空间
- [x] T1.6: 全面重新设计 UI（现代化卡片式、渐变色、阴影、动效）

- [ ] T2: 引入 `CameraVerifier` 服务（精准判定）
  - [ ] T2.1: 新建 `NetSecurityScanner.Core/Services/CameraVerifier.cs`，定义 `VerificationResult { IsCamera, Confidence, Vendor, Method, Evidence }`
  - [ ] T2.2: 实现多级验证流程：端口启发 → 厂商关键字 → HTTP 指纹 → RTSP DESCRIBE → ONVIF GetCapabilities
  - [ ] T2.3: 引入 `CameraFingerprintDB.json` 加载（含海康/大华/宇视/萤石/雄迈/天地伟业/汉邦/朗驰/同为/小厂 ≥ 30 条规则）
  - [ ] T2.4: 单元测试：5 个真实摄像头 IP 模拟 + 5 个非摄像头（路由/NAS/打印机）模拟，识别率 ≥ 95%，误报率 < 5%

- [x] T3: 反例过滤（路由器/打印机/NAS 不被误判）
  - [ ] T3.1: 在 `CameraVerifier` 中添加 `IsLikelyNotCamera(httpResponse, serverHeader)` 方法
  - [ ] T3.2: 维护反例黑名单关键词：D-Link Router / TP-LINK Router / Synology / QNAP / HP Printer / Brother Printer / MikroTik / iStoreOS / OpenWrt / Windows
  - [ ] T3.3: 黑名单命中 → 直接返回 IsCamera=false，Confidence=0

- [x] T4: 厂商默认端口探测
  - [ ] T4.1: 在 `CameraDiscoveryService` 中添加 `_vendorPorts` 字典（每个厂商 3-5 个默认端口）
  - [ ] T4.2: 扫描时优先并发探测这些端口（替代 554/80/8080 默认值）
  - [ ] T4.3: 端口列表：
        Hikvision: 80, 554, 8000, 8080, 8200
        Dahua:     80, 554, 37777, 8080, 34567
        Uniview:   80, 554, 34567, 8080
        Tiandy:    80, 554, 6036, 8080
        TP-Link:   80, 554, 2020, 8080
        EZVIZ/萤石: 80, 554, 8000, 8001
        Axis:      80, 443, 554, 8080
        Bosch:     80, 443, 554, 8080
        Hanwha:    80, 443, 554, 8080
        Onvif通用:  80, 554, 8080, 8899

- [ ] T5: 在结果列表展示"判定依据"
  - [ ] T5.1: `CameraScanResult` 新增 `VerificationMethod` 字段（HTTP指纹/RTSP响应/ONVIF协议/端口启发/未知）
  - [ ] T5.2: DataGrid 新增"判定依据"列
  - [ ] T5.3: 鼠标悬浮单元格显示 Evidence 详情

- [x] T6: 编译验证 + 集成测试
  - [ ] T6.1: `dotnet build` 通过（0 错误）
  - [ ] T6.2: 启动应用，打开"摄像头安全扫描"，确认主窗口已简化
  - [ ] T6.3: 高级按钮可调出标签/弱口令/趋势入口
  - [ ] T6.4: 在测试靶场（DeepScanTest 已知端口）跑通精准识别

# Task Dependencies
- T2 (CameraVerifier) 依赖 T3 (反例过滤) 和 T4 (厂商端口)
- T5 (展示判定依据) 依赖 T2 (CameraVerifier)
- T6 (集成测试) 依赖 T1-T5 全部完成

# 验证清单
- [ ] 主窗口 RiskDashboard 已移除，整体高度减小
- [ ] 高级按钮可调出标签/弱口令/趋势入口
- [ ] 扫描真实摄像头环境时识别准确度提升（无量化数据时记录日志佐证）
- [ ] 路由器/NAS/打印机不被误判
- [ ] 0 编译错误
