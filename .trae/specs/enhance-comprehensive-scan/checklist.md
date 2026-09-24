# Checklist

## 服务层(`ComprehensiveScanService`)
- [ ] `ComprehensiveScanOptions` 含 11 个字段(TargetIp/Preset/CustomPorts/EnableTcp/EnableUdp/EnableVulnScan/EnablePluginScan/Concurrency/TimeoutSeconds/RetryCount/SaveToHistory/HostDiscoveryTimeoutMs)
- [ ] `ComprehensiveScanResult` 含 15 个字段(ScanId/TargetIp/ScanType/ScanTime/ScanDurationSeconds/HostAlive/TcpOpenPorts/UdpOpenPorts/AllPortResults/VulnerabilityResults/PluginResults/RiskLevel/Phases/HasVulnerabilityScanError/HasPluginScanError/Cancelled)
- [ ] `ScanPhaseProgress` 含 7 字段 + `enum ScanPhase` 7 个阶段值
- [ ] `ScanPresetRegistry` 提供 6 个内置预设(Quick/Standard/Deep/Web/Database/Custom)
- [ ] `ScanPresetRegistry.ParsePortList("1-100,443,8080-8090")` 返回 103 个去重排序端口
- [ ] `ComprehensiveScanService.ExecuteAsync` 按 6 阶段串行执行,异常隔离不阻断后续
- [ ] 主机存活探测阶段超时 3 秒(ICMP + 80/443 TCP 回退),失败时 `HostAlive=false` 但继续扫描
- [ ] TCP+UDP 端口扫描并发执行(`Task.WhenAll`),合并进度
- [ ] 漏洞扫描/插件扫描异常被 try/catch 捕获,只标记 Phase 失败,继续
- [ ] 风险等级计算沿用现有规则(严重/高/中/低/无)
- [ ] `SaveToHistory=true` 时按"先存结果+再更新历史"顺序调 `JsonDatabaseService`(原 `MainWindow` 行为)

## 实时进度窗口(`ScanProgressLiveWindow`)
- [ ] 6 阶段步骤条,当前阶段高亮,已完成阶段打勾
- [ ] 主进度条 + 阶段内子进度
- [ ] 已发现开放端口列表实时追加
- [ ] 已用时间 / 估算剩余时间显示
- [ ] 暴露 `IProgress<ScanPhaseProgress> Progress` 和 `CancellationToken`
- [ ] 取消按钮能中止扫描 + 关闭窗口
- [ ] 窗口关闭时自动 Cancel(避免泄漏)

## 富文本结果窗口(`ComprehensiveScanResultWindow`)
- [ ] 5 个 Tab:概览/端口/漏洞/服务/插件
- [ ] 概览 Tab 显示目标/扫描类型/耗时/HostAlive/各阶段耗时/风险等级徽章
- [ ] 端口 Tab 5 列(Port/Protocol/Status/Service/Version)支持列排序
- [ ] 漏洞 Tab 6 列 + 风险筛选 ComboBox
- [ ] 服务 Tab 按服务聚合
- [ ] 插件 Tab 5 列
- [ ] 4 个底部按钮:导出 JSON / 导出 CSV / 对比历史 / 复制为 Markdown
- [ ] 导出文件默认名 `综合扫描_{ip}_{timestamp}.{json|csv}`
- [ ] 复制为 Markdown 后 `Clipboard.GetText()` 包含目标/端口数/漏洞数/风险等级/扫描阶段摘要

## 配置对话框(`ComprehensiveScanDialog`)
- [ ] 6 个预设下拉(Quick/Standard/Deep/Web/Database/Custom)
- [ ] 选择预设自动填端口,选 Custom 时端口框可编辑
- [ ] 并发数/超时/重试次数 3 个 NumericUpDown
- [ ] 4 个开关(TCP/UDP/漏洞/插件)
- [ ] 右侧实时预览:端口数 / 估算耗时 / 最近同目标扫描
- [ ] IP 格式 + 端口格式 + 至少一个协议 3 重验证
- [ ] 验证通过调 `BuildOptions() → ComprehensiveScanOptions` 后 `DialogResult=true`

## MainWindow 瘦身
- [ ] 删除 `ExecuteComprehensiveScanAsync` 旧实现(230+ 行)
- [ ] 删除私有 `ParsePortRange`(如有)
- [ ] `StartScan_Click` 行数 ≤ 30
- [ ] `StartScan_Click` 内只做"弹对话框→调服务→弹结果窗"3 步
- [ ] 任何业务逻辑(端口解析/进度计算/风险计算/历史保存)都不再出现在 MainWindow

## 编译与启动
- [ ] `dotnet build -c Release` 0 编译错误
- [ ] 所有新增 XAML 文件通过 BAML 编译
- [ ] DLL FileVersion 保持 1.0.1.2(本任务不涉及版本号变更)
- [ ] 启动程序无异常
- [ ] 菜单"扫描 → 开始综合扫描"能弹出 `ComprehensiveScanDialog`

## 运行时冒烟
- [ ] `Standard` 预设 + 全开扫描 127.0.0.1 能完成,结果窗口 5 个 Tab 有数据
- [ ] `Quick` 预设扫描公网 IP,`HostAlive=false` 但其他阶段仍执行
- [ ] 进度窗口取消按钮能中止扫描
- [ ] 导出 JSON + CSV 文件能成功写入
- [ ] 同一目标二次扫描,对比历史能看到新增/消失
