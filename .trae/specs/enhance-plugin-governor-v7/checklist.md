# v7 验证清单

## 签名校验
- [ ] `PluginSignatureService` 能加载并解析 `.sig` 文件
- [ ] 签名匹配白名单公钥 → 加载继续
- [ ] 签名不在白名单 / 缺失 / 被篡改 → 抛 `PluginSignatureException`
- [ ] 签名失败写审计 `SignatureInvalid`（含 SHA-256 指纹）
- [ ] `RequireSignature=false` 时跳过签名校验（仅审计）
- [ ] `SignAsync(dllPath, privateKeyPath)` 工具方法能正确生成签名

## 沙箱隔离
- [ ] 插件越界读 `C:\Windows\System32\...` 抛 `SandboxViolationException`
- [ ] 插件访问未授权域名 `attacker.com` 被拦截
- [ ] 插件启动未授权进程被拦截
- [ ] 插件访问未授权注册表键被拦截
- [ ] 沙箱违规写审计 `SandboxViolation` + 取消当前执行
- [ ] 合规调用（白名单内路径/域名）正常放行
- [ ] 宽松模式下仅记录不阻断

## 调用链追踪
- [ ] 每次扫描生成唯一 TraceId
- [ ] 每个插件执行生成独立 SpanId（含父 SpanId）
- [ ] Span 写入 `data/plugin_traces/{yyyyMMdd}.jsonl`（5 秒批量 flush）
- [ ] `QueryTraceAsync(traceId)` 返回完整调用树
- [ ] Span > 30 秒触发 `OnTraceTimeout` 事件 + 健康扣 10 分
- [ ] `PluginOrchestrator` 透传 TraceId 到所有子调用

## 远程管控 API
- [ ] Kestrel 监听 `127.0.0.1:9530` 启动成功
- [ ] 无 JWT 请求返回 401 + 审计 `RemoteApiUnauthorized`
- [ ] 有效 JWT GET `/api/v7/governor/status` 返回正确 JSON
- [ ] POST `/api/v7/plugins/{id}/quarantine` 实际隔离插件 + 审计
- [ ] POST `/api/v7/plugins/{id}/release` 实际解除隔离 + 审计
- [ ] GET `/api/v7/traces/{traceId}` 返回链路详情
- [ ] GET `/api/v7/alerts/recent?limit=50` 返回最近告警
- [ ] `GenerateTempJwtAsync(user, ttl)` 生成的 JWT 2 小时后过期
- [ ] 关闭主程序时 Kestrel 优雅停止（无连接泄漏）

## 权限申请工作流
- [ ] 插件调 `RequestPermissionAsync` 创建待审批申请
- [ ] 待审批申请持久化到 `data/permission_requests.json`
- [ ] 管理员在管控中心"权限审批"Tab 看到申请列表
- [ ] 批准后 `PluginPolicy.PermissionMatrix` 自动更新
- [ ] 批准后审计 `PermissionGranted` + 备注
- [ ] 拒绝后申请标记 `Rejected` + 审计
- [ ] 拒绝后插件 1 小时内再次申请同权限直接拒绝
- [ ] 批准后沙箱同步放行新权限
- [ ] 权限申请时系统托盘弹通知

## 告警模板
- [ ] 8 个内置模板可一键启用
- [ ] 启用后创建 `AlertRule`（阈值/渠道预填）
- [ ] 模板启用写审计 `AlertTemplateEnabled`
- [ ] 自定义阈值的规则标记 `IsCustomized=true` 不再跟随模板更新
- [ ] 启用的告警规则立即生效

## 运行时大屏
- [ ] 第 5 个 Tab "🩺 运行时大屏" 可正常打开
- [ ] 4 个 KPI 卡片 5 秒自动刷新
- [ ] LiveCharts2 折线图（健康度/内存/调用链耗时）正常渲染
- [ ] 折线图 5 秒追加新数据点
- [ ] 事件流 ListView 显示最近 100 条告警/隔离/签名失败
- [ ] 点击事件行跳到对应插件详情
- [ ] 隔离事件触发后 KPI 卡片"隔离数"自动 +1

## 权限审批 UI
- [ ] 第 6 个 Tab "权限审批" 显示待审批申请列表
- [ ] "通过" / "拒绝" 按钮带备注输入框（必填）
- [ ] 提交后状态实时更新

## 告警模板 UI
- [ ] 第 7 个 Tab "告警模板" 显示 8 个模板卡片
- [ ] "启用" 按钮可一键创建告警规则
- [ ] 启用后立即在"调度与告警"Tab 看到新规则

## 审计导出 & SIEM
- [ ] 选 7 天日期范围能合并导出 CSV
- [ ] CSV 含 UTF-8 BOM（Excel 直接打开无乱码）
- [ ] CSV 列：时间 / 操作人 / pluginId / action / result / detail
- [ ] 配置 SYSLOG-UDP 后审计实时推送
- [ ] 配置 HTTP-JSON 后审计实时推送到 ELK
- [ ] SIEM 推送失败写 dead-letter
- [ ] dead-letter 每 30 秒自动重试
- [ ] "导出审计" + "SIEM 配置" 按钮在管控中心可见可点

## 远程管控台
- [ ] "🌐 远程管控" 按钮在 `PluginManagerWindow` 顶栏（admin only）
- [ ] `RemoteGovernorConsoleWindow` 显示 API URL + 临时 JWT
- [ ] "复制 JWT" 用 STA 线程方案（不冻结 UI）
- [ ] "打开浏览器" 跳到默认浏览器查看 API 文档
- [ ] 显示最近 10 个 API 调用记录

## 加载流程升级
- [ ] `PluginHotLoader.Enable` 顺序：签名 → 沙箱 → 权限
- [ ] 任一步骤失败 → 拒绝 + 审计 + 抛出对应异常
- [ ] 失败步骤的异常信息清晰（签名失败 vs 沙箱违规 vs 权限不足）

## 健康监控升级
- [ ] CPU 采样改为 `Process.TotalProcessorTime` 真实值
- [ ] 订阅 `OnTraceTimeout` 事件触发健康扣分
- [ ] 隔离前 5 分钟"冷却期"避免抖动
- [ ] 健康度评分公式：失败 30% + 内存 30% + CPU 20% + 超时 20%
- [ ] 健康度排行榜显示 CPU 使用率

## 集成
- [ ] `PluginGovernor.Instance` 暴露 10 个子服务（4 个 v6 + 6 个 v7）
- [ ] `PluginHotLoader.Enable` 集成 v7 三段校验
- [ ] `PluginManager.ScanWithPluginsForTargetAsync` 埋点 Telemetry
- [ ] `PluginOrchestrator.ScanTargetAsync` 透传 TraceId
- [ ] 重复 `InitializeAsync()` 幂等
- [ ] `MainWindow` 关闭时 `await PluginGovernor.Instance.DisposeAsync()` 优雅释放

## 构建 & 启动
- [ ] `dotnet build -c Release` 0 错误 0 警告
- [ ] 主程序启动 0 异常，Governor v7 全部子服务启动
- [ ] 重启主程序不重复初始化（幂等）
- [ ] 应用退出时 Kestrel / 沙箱 / 链路 flush 全部正常释放
- [ ] 远程 API 服务在主进程退出时正常停止
