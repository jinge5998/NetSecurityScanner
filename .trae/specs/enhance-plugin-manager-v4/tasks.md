# v4 Tasks

- [ ] v4-T1: 增强 4 个内置插件扫描深度
  - [ ] v4-T1.1: SslTlsPlugin 新增 Heartbleed (CVE-2014-0160) PoC 探测
  - [ ] v4-T1.2: SslTlsPlugin 新增 POODLE (CVE-2014-3566) 检测（禁用 SSLv3）
  - [ ] v4-T1.3: PortServicePlugin 新增 30+ 服务版本签名匹配（OpenSSH、Apache、Nginx、IIS 等）
  - [ ] v4-T1.4: WeakPasswordPlugin 扩展默认凭据字典到 50+（admin/admin、admin/12345、root/root、ubnt/ubnt、Hikvision 默认等）
  - [ ] v4-T1.5: WeakPasswordPlugin 新增 Telnet/SSH 协议 NVT 协商探测
  - [ ] v4-T1.6: WebVulnPlugin 新增 30+ 敏感路径爆破（/admin /phpinfo.php /.env /actuator /manager/html /wp-admin 等）
  - [ ] v4-T1.7: WebVulnPlugin 新增 HTTP 安全头缺失检测（X-Frame-Options、X-Content-Type-Options、Strict-Transport-Security 等）
  - [ ] v4-T1.8: WebVulnPlugin 新增 SQL 注入基础 payload 探测（单引号、union select、or 1=1）

- [ ] v4-T2: 新增插件商店 UI
  - [ ] v4-T2.1: `Services/PluginMarketCatalogService.cs` 提供本地 mock 目录（10+ 插件：Hikvision 弱口令扫描、ONVIF 枚举、SSL 评分、合规检查 等）
  - [ ] v4-T2.2: `Views/Views/PluginMarketWindow.xaml` 主窗口：搜索框 + 分类下拉 + DataGrid 展示
  - [ ] v4-T2.3: `Views/Views/PluginMarketWindow.xaml.cs` 实现搜索/分类过滤 + 安装/卸载回调
  - [ ] v4-T2.4: `PluginManagerWindow.xaml` 顶部新增"插件商店"按钮，调用 PluginMarketWindow
  - [ ] v4-T2.5: 安装完成后 PluginManager 自动重新加载新插件

- [ ] v4-T3: 插件执行日志与统计
  - [ ] v4-T3.1: `Models/PluginExecutionEntry.cs` { PluginId, PluginName, Target, Port, StartTime, EndTime, DurationMs, Status (Success/Failed/Timeout), VulnCount, ErrorMessage }
  - [ ] v4-T3.2: `Services/PluginExecutionLogService.cs` 提供 `LogExecutionAsync` 写入 `data/plugin_executions/{yyyyMMdd}/{id}.json`
  - [ ] v4-T3.3: `Services/PluginExecutionLogService.cs` 提供 `GetStatisticsAsync(days=7)` 返回总执行数/成功率/平均耗时/失败 TOP5
  - [ ] v4-T3.4: `Views/Views/PluginExecutionLogWindow.xaml` 主窗口：顶部 4 个统计卡片 + 底部 DataGrid（最近 50 条）
  - [ ] v4-T3.5: `Views/Views/PluginExecutionLogWindow.xaml.cs` 实现加载/刷新/异常高亮
  - [ ] v4-T3.6: `PluginManagerWindow.xaml` 顶部新增"执行日志"按钮
  - [ ] v4-T3.7: `PluginManager.ScanWithPluginsForTargetAsync` 集成日志服务（每个插件执行前后记录）

- [ ] v4-T4: 插件沙箱与资源限制
  - [ ] v4-T1.1: `Plugins/PluginSandboxService.cs` 提供 `ExecuteSafelyAsync(plugin, context, timeout=30s)`
  - [ ] v4-T1.2: 实现 SemaphoreSlim 并发限流（最多 3 个插件同时）
  - [ ] v4-T1.3: 实现 CancellationToken 超时强制取消
  - [ ] v4-T1.4: 实现全局 try-catch + AggregateException 包装
  - [ ] v4-T1.5: 实现资源监控（耗时、异常内存增长报警）
  - [ ] v4-T1.6: `PluginManager.ScanWithPluginsForTargetAsync` 改为通过沙箱服务调用

- [x] v4-T5: 编译验证
  - [ ] v4-T5.1: 编译主程序项目（0 错误）
  - [ ] v4-T5.2: 启动程序打开 PluginManagerWindow 验证新增按钮可点击
  - [ ] v4-T5.3: 打开插件商店窗口，验证 10+ mock 插件显示正常
  - [ ] v4-T5.4: 打开执行日志窗口，验证统计卡片和记录显示
  - [ ] v4-T5.5: 综合扫描 192.168.3.92 验证插件执行 + 沙箱 + 日志 全部生效

# v4 Task Dependencies
- v4-T1 独立（修改内置插件）
- v4-T2 独立（新增商店窗口）
- v4-T3 依赖 v4-T4（日志需要在沙箱内记录）
- v4-T4 独立（新增沙箱服务）
- v4-T5 依赖所有任务
