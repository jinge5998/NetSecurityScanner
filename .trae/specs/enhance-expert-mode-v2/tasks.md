# Tasks

- [x] Task 1: Rust IPC 扫描模式集成
  - [x] SubTask 1.1: 在 ExpertModeWindow 增加 `_useRustScanner` 字段，从 PluginGovernor 策略读取默认值
  - [x] SubTask 1.2: 在性能调优 Tab 增加「扫描引擎」切换区（Rust / 内置C#），显示当前引擎状态
  - [x] SubTask 1.3: 改造 `ExecuteExpertScanAsync`，Rust 模式走 `RustScannerClient.ScanPortsAsync`，内置模式走 `PortScanner`
  - [x] SubTask 1.4: Rust 扫描结果回传时实时更新 DataGrid（流式 IPC）
  - [x] SubTask 1.5: Rust 不可用时自动降级并在日志中提示

- [x] Task 2: 扫描历史与差异对比 Tab
  - [x] SubTask 2.1: 新增 Tab 7「📊 扫描历史」，DataGrid 列出历史记录（从 JsonDatabaseService 读取）
  - [x] SubTask 2.2: 支持多选两条记录点击「对比」，弹出 ScanDiffWindow 显示差异（新增/关闭端口、新增/修复漏洞）
  - [x] SubTask 2.3: ScanDiffWindow 用左右双栏布局，差异行用颜色标注

- [x] Task 3: 定时扫描 Tab
  - [x] SubTask 3.1: 新增 Tab 8「⏰ 定时扫描」，支持「仅一次 / 每天 / 每周 / 自定义 Cron」
  - [x] SubTask 3.2: 填写目标 + Cron 模式后调 `PluginScheduler.AddTask` 创建定时任务
  - [x] SubTask 3.3: 显示当前已有定时任务列表，支持启用/禁用/删除

- [x] Task 4: 结果交互增强
  - [x] SubTask 4.1: 端口 DataGrid 行双击弹出详情（含完整信息 + 服务 Banner + 关联漏洞）
  - [x] SubTask 4.2: 漏洞 DataGrid 行双击弹出详情（含 CVE 描述 + 修复建议）
  - [x] SubTask 4.3: 端口行右键菜单增加「针对此端口深度漏洞扫描」
  - [x] SubTask 4.4: 扫描开始时自动切换到「实时结果」Tab

- [x] Task 5: 导出增强
  - [x] SubTask 5.1: 新增「📕 导出 PDF」按钮
  - [x] SubTask 5.2: ExportNmapButton 的 Clipboard.SetText 改为 STA 线程安全复制（4 次重试）
  - [x] SubTask 5.3: 所有导出按钮的 Clipboard 操作统一使用 SafeSetClipboard 方案

- [x] Task 6: 预设管理增强
  - [x] SubTask 6.1: SavePresetButton 点击后弹出输入对话框输入预设名称
  - [x] SubTask 6.2: LoadPresetButton 点击后弹出列表选择对话框（支持删除）
  - [x] SubTask 6.3: 预设保存到 `%LOCALAPPDATA%\NetSecurityScanner\expert_presets\{name}.json`
  - [x] SubTask 6.4: Nmap 模板按钮点击后改为页面内绿色提示条（3 秒自动消失，替代 MessageBox）

- [x] Task 7: 智能推荐集成
  - [x] SubTask 7.1: 目标配置区增加「💡 推荐模式」按钮，基于 ScanProfileConfigFactory 生成推荐
  - [x] SubTask 7.2: 推荐结果显示在目标配置区下方，包含推荐模式和理由
  - [x] SubTask 7.3: 点击推荐结果自动应用对应的 ScanProfileConfig 参数

- [x] Task 8: 目标解析与进度增强
  - [x] SubTask 8.1: CIDR/Range 解析超过 256 个目标时弹出确认警告
  - [x] SubTask 8.2: 目标输入区增加「📋 从剪贴板粘贴」按钮
  - [x] SubTask 8.3: 实时结果 Tab 底部增加「已用时间 / 预计剩余时间」显示
  - [x] SubTask 8.4: 扫描开始时自动切换到实时结果 Tab

- [x] Task 9: 配置自动恢复
  - [x] SubTask 9.1: 窗口关闭时将当前配置序列化到 `%LOCALAPPDATA%\NetSecurityScanner\expert_last_config.json`
  - [x] SubTask 9.2: 窗口打开时读取并恢复上次配置（Tab 选项、目标类型、端口模式、高级参数等）

- [x] Task 10: 验证 & 构建
  - [x] SubTask 10.1: `dotnet build -c Debug` 0 错误
  - [x] SubTask 10.2: 核心场景已通过编译验证

# Task Dependencies
- Task 1 依赖 RustScannerClient 已存在（已完成）
- Task 2 依赖 JsonDatabaseService 已存在（已完成）
- Task 3 依赖 PluginScheduler 已存在（已完成）
- Task 5 PDF 导出依赖 ReportEngine 已存在（已完成）
- Task 7 依赖 ScanProfileConfig + ScanProfileConfigFactory 已存在（已完成）
- Task 4, 5, 6, 7, 8, 9 之间相互独立，已并行完成
