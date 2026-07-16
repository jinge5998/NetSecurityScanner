# v6 验证清单

## 安全治理
- [x] `PluginGovernor.Instance` 全局唯一（多次调用不重复构造）
- [x] `PluginPolicy.json` 首次启动自动创建（含默认白名单空/黑名单空/全部权限默认允许）
- [x] 黑名单插件被加载时抛 `PluginBlockedException`
- [x] 危险操作（写注册表/删文件/启动进程）未授权时抛 `PermissionDeniedException`
- [x] 每次 install/uninstall/enable/disable/execute/upgrade/policyChange 均在 `data/plugin_audit/{yyyyMMdd}.json` 追加一条
- [x] 审计条目包含：时间戳 / 操作人 / pluginId / action / before/after / 结果
- [x] 策略修改保存后立即生效（无需重启）
- [x] 30 天前的审计文件自动归档到 `data/plugin_audit/archive/`

## 版本与依赖
- [x] 启动时 `CheckUpdatesAsync()` 在后台异步执行
- [x] 管控中心"版本与依赖"页签显示待更新数量徽章
- [x] 升级前旧版本自动备份到 `Plugins/backup/{id}_{ver}/`
- [x] 升级后审计日志记录备份路径
- [x] core 版本不满足时拒绝升级
- [x] 从 backup/ 回滚到任意历史版本成功
- [x] 依赖图可视化（已满足=绿，缺失=红，版本过低=黄）
- [x] 缺失依赖点击"一键安装"自动从商店拉取

## 健康监控
- [x] 后台 5 秒采样（仅 LoadedPlugins）
- [x] 5 分钟内连续 3 次失败自动隔离
- [x] 隔离后从 `LoadedPlugins` 移除 + 审计 + 托盘通知
- [x] 单次内存增量 > 200 MB 触发熔断（取消当前执行）
- [x] 健康度评分 < 60 触发告警
- [x] 健康度排行榜按评分倒序展示
- [x] 双击排行行展示该插件最近 50 次执行详情

## 调度与告警
- [x] Cron 5/6 段表达式解析正确
- [x] 后台定时器每分钟唤醒
- [x] 失败指数退避重试（1/2/4/8/16s，最多 5 次）
- [x] 系统托盘通知（NotifyIcon.ShowBalloonTip）正常弹出
- [x] 告警日志追加到 `logs/alerts/{yyyyMMdd}.log`
- [x] 定时任务持久化到 `data/scheduled_tasks.json`
- [x] 告警规则持久化到 `data/alert_rules.json`
- [x] 应用关闭时优雅释放调度器后台线程

## 集成
- [x] `PluginHotLoader.Enable()` 先校验黑名单再校验权限
- [x] `PluginManager.ScanWithPluginsForTargetAsync` 埋点 HealthMonitor
- [x] `PluginExecutionLogService.LogExecutionAsync` 同步写审计
- [x] `PluginOrchestrator.ScanTargetAsync` 调用前 `PluginGovernor.Instance.ValidateScanRequestAsync`
- [x] 重复 `InitializeAsync()` 只生效一次

## UI
- [x] `PluginGovernorWindow` 4 页签渲染正常
- [x] "🛡  管控中心"按钮仅 admin 可见可点；其他角色置灰 + ToolTip 提示
- [x] 顶部状态栏显示：Governor 健康度 / 待更新数 / 隔离数 / 调度任务数
- [x] 审计日志支持按日切换
- [x] 依赖图 TreeView 节点可点击"一键安装"

## 构建 & 启动
- [x] `dotnet build -c Release` 0 错误 0 警告（仅历史警告，与本特性无关）
- [x] 主程序启动 0 异常，Governor InitializeAsync 完成
- [x] 重启主程序不重复初始化（幂等）
- [x] 应用退出时所有后台线程正常释放
