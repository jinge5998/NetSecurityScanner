# Checklist - 简化摄像头扫描 UI + 提升检测准确度

## UI 简化
- [ ] RiskDashboard 5 张风险卡片从 XAML 中删除
- [ ] VendorBarChart/LineChart/RiskGauge 从 XAML 中删除
- [ ] Grid Row 索引调整正确，无错位
- [ ] 标题栏、目标输入、扫描选项、日志、结果列表 5 个区域按顺序排列
- [ ] 主窗口高度从 ~880px 缩减到 ~680px
- [ ] 工具栏新增"高级"按钮，下拉含标签/弱口令/趋势 3 个入口
- [ ] UpdateDashboard / VendorChart / DailyChart / RiskGauge 代码引用清理

## 检测准确度
- [ ] CameraVerifier 服务实现并集成
- [ ] 多级验证流程（端口 → 厂商关键字 → HTTP → RTSP → ONVIF）
- [ ] CameraFingerprintDB.json 含 ≥ 30 条规则
- [ ] 反例黑名单命中 → IsCamera=false
- [ ] 厂商默认端口表完整（10 个厂商）
- [ ] 单元测试 5 真 + 5 假识别率 ≥ 95%，误报 < 5%

## 结果展示
- [ ] DataGrid 新增"判定依据"列
- [ ] VerificationMethod 字段写入 CameraScanResult
- [ ] 悬浮显示 Evidence 详情

## 质量门禁
- [ ] `dotnet build` 0 错误
- [ ] 启动应用打开摄像头扫描窗口 UI 正常
- [ ] 高级按钮菜单可正常打开子窗口
- [ ] 与 DeepScanTest 集成测试不冲突
