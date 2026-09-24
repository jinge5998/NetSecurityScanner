# v4 验证清单

- [x] SslTlsPlugin 对支持 Heartbleed 的目标返回 `CVE-2014-0160 Heartbleed 严重` 报告
- [x] SslTlsPlugin 对启用 SSLv3 的目标返回 `CVE-2014-3566 POODLE 中危` 报告
- [x] PortServicePlugin 正确识别 OpenSSH 7.4 → 报告 `CVE-2018-15473 用户枚举`（12 个服务签名覆盖）
- [x] WeakPasswordPlugin 用 52+ 默认凭据测试 Hikvision、Dahua、TP-Link、D-Link、海视云、雄迈、ONVIF、Axis、Bosch、天地伟业、补充 DVR 后门
- [x] WebVulnPlugin 对 /.env 返回 200 且包含 `DB_PASSWORD=` 时报告（46 个敏感路径 + 特征二次确认）
- [x] WebVulnPlugin 对缺少 X-Frame-Options / X-Content-Type-Options / HSTS / CSP / X-XSS-Protection 的 HTTP 服务报告
- [x] WebVulnPlugin 对 `?id=1'` 返回 500 错误时报告"可能存在 SQL 注入"（基于长度差异/状态码/SQL 错误关键字三条件）
- [x] 插件商店窗口显示 12 个 mock 插件（Hikvision 弱口令/ONVIF 枚举/SSL 评分/SSH 弱口令深度/HTTP 敏感信息泄露/FTP 匿名/Redis 未授权/工控协议/数据库弱口令/摄像头固件/SNMP/路由器默认）
- [x] 商店窗口搜索 "弱口令" 过滤出相关插件（`SearchAsync` 实现）
- [x] 商店窗口点击"安装" 后 PluginManagerWindow 出现新插件（`MarketButton_Click` + `RefreshAfterMarket`）
- [x] 执行日志窗口显示 4 个统计卡片（总执行数/成功率/平均耗时/失败数，`CreateStatsPanel` 实现）
- [x] 执行日志窗口显示最近 50 条记录，失败/超时/取消行红色背景（`RowStyle` DataTrigger）
- [x] 扫描完成后日志文件 `data/plugin_executions/{yyyyMMdd}/*.json` 正常生成（`LogExecutionAsync` + `DataPaths.DataRoot`）
- [x] 插件卡死 30 秒后被沙箱超时取消（`SemaphoreSlim(3,3)` + `CancellationTokenSource(30s)`），不影响其他插件
- [x] 插件抛未捕获异常时沙箱捕获并记录（`OperationCanceledException`→Timeout/Cancelled, 其他→Failed），不拖垮主程序
- [x] 编译无错误（0 错误 0 警告）
- [x] 启动后 PluginManagerWindow 显示"插件商店"和"执行日志"两个新按钮（`PluginManagerWindow.xaml.cs:150-154`）
