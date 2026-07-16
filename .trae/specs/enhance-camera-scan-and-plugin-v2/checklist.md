# Checklist

- [ ] CameraScanResult 新增 6 个字段
- [ ] CameraScanSession 模型创建并支持 JSON 持久化
- [ ] CameraScanTemplate 至少内置 3 个模板（海康/大华/通用）
- [ ] CameraMonitorService 支持 5/10/30/60 分钟监控间隔
- [ ] 摄像头扫描窗口新增"持续监控"选项卡
- [ ] 定时任务 cron 编辑器可用
- [ ] 会话回放窗口显示时间线
- [ ] 告警通过系统通知弹出
- [ ] Plugin 新增 6 个字段
- [ ] PluginSignature 工具类实现 RSA 签名校验
- [ ] 签名缺失/失效时拒绝加载并记录日志
- [ ] SemVer 版本比较正确
- [ ] 插件热加载不需重启
- [ ] 评分/评论/版本历史在市场页面可见
- [ ] 持续监控 5 分钟无内存泄漏
- [ ] 所有新功能编译通过（0 错误）
- [ ] 自包含发布版（71MB）正常启动

# v3 验证清单

- [x] 摄像头告警去重：同 IP+Type 24h 内只产生 1 条
- [x] 系统托盘通知真实弹出（标题、消息、图标）
- [x] 严重级别告警触发邮件
- [x] cron 表达式 `*/5 * * * *` 正确触发（每 5 分钟）
- [x] 监控任务连续失败 5 次自动禁用并产生告警
- [x] 扫描基线保存 → 后续扫描正确标注 Added/Removed/Changed
- [x] 黑名单中的 IP 被跳过扫描
- [x] 白名单中的 IP 永不产生告警
- [x] 模板导出为 JSON 后可从 JSON 重新导入
- [x] PluginSignature 用真实密钥对签名后，验证通过
- [x] PluginSignature 用错误公钥验证失败
- [x] AssemblyLoadContext 卸载后 DLL 句柄释放（可重新写入）
- [x] 插件 Permissions 字段正确显示在市场窗口
- [x] 插件自动更新检测返回正确的可更新列表
- [x] 依赖环 A→B→C→A 抛 InvalidOperationException
- [x] 插件回滚到上一版本成功
- [x] v3 所有新增功能编译通过（0 错误）
