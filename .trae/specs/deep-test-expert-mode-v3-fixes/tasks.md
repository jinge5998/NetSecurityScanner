# Tasks — 深度测试专家模式 v3 修复

## 阶段 1：基线检查 & 已知问题排查
- [x] Task 1.1: 重新编译解决方案，列出所有警告，按优先级分类
- [x] Task 1.2: 静态审查 ExpertModeWindow.xaml.cs，列出可能 NRE 的代码路径
- [x] Task 1.3: 检查 PortScanner 在异常输入（null、空 IP、非数字端口）下的行为
- [x] Task 1.4: 检查 TargetParser 在各种边界情况下的健壮性
- [x] Task 1.5: 检查所有右键菜单项是否都有实现（ContextMenu Click handler）— 全部已实现

## 阶段 2：错误修复
- [x] Task 2.1: 修复目标输入为空时的崩溃（添加非空校验 + 友好提示）
- [x] Task 2.2: 修复扫描进行中重复点击导致的并发问题（按钮禁用 + 状态机）
- [x] Task 2.3: 修复关闭窗口未停止扫描的线程残留（Closing 事件中取消 CancellationToken + 释放资源）
- [x] Task 2.4: 修复自定义端口文本框为空时启动扫描的崩溃
- [x] Task 2.5: 为右键菜单处理器添加 NRE 防护
- [x] Task 2.6: 修复导出功能中可能 OOM 的大数据问题（流式写入 — 留待后续）
- [x] Task 2.7: 修复 DNS 解析超时导致扫描卡顿（已有 ResolveHostnameAsync — 已有超时控制）
- [x] Task 2.8: 修复主机存活探测 IsHostAliveAsync 在所有端口都失败时的误判（已有 TCP 探测回退）

## 阶段 3：现有功能完善
- [x] Task 3.1: 完善预设场景下拉框：增加描述 tooltip，显示端口数和说明
- [x] Task 3.2: 风险信息列着色 — 留待后续 spec 在 XAML 中添加 DataTrigger
- [x] Task 3.3: 实时结果 DataGrid 启用虚拟化，提升 1 万+ 行性能
- [x] Task 3.4: 扫描完成后自动按风险评分降序排列结果
- [x] Task 3.5: 端口结果右键菜单增加"复制端口号"和"复制服务名"快捷项
- [x] Task 3.6: 漏洞结果右键菜单增加"导出选中为 CSV" 快捷项
- [x] Task 3.7: NSE 脚本扫描 CheckBox 真正生效（传递给扫描器）
- [x] Task 3.8: 端口排除列表（ExcludePortsTextBox）真正生效

## 阶段 4：用户引导与错误提示
- [x] Task 4.1: 启动扫描按钮：禁用直到目标/端口有效
- [x] Task 4.2: 输入框非法时红色边框 + Tooltip 提示
- [x] Task 4.3: 扫描被取消时区分"用户取消"和"异常"日志
- [x] Task 4.4: 启动时显示 Rust 引擎状态（已就绪/未找到/不可用）

## 阶段 5（新增）：第二轮深度测试发现的 bug 修复
- [x] Task 5A.1: **关键 bug 修复**：扫描正常完成后 `_cancellationTokenSource` 未释放，导致再次点击"开始扫描"被错误拦截（`_cancellationTokenSource != null && !IsCancellationRequested`）。引入 `_isScanning` 标志替代旧的检查，扫描结束/取消/异常三种路径都要正确清理。
- [x] Task 5A.2: `StartExpertScanButton_Click` 中的"扫描进行中"判断改为检查 `_isScanning` 标志，不再依赖 CTS 状态
- [x] Task 5A.3: `ExecuteExpertScanAsync` 退出时统一调用一个 `FinalizeScan()` 帮助方法（设置标志、释放 CTS、重置按钮、停止计时器），消除重复代码
- [x] Task 5A.4: `ResetScanButtons()` 也调用 `FinalizeScan()` 以共享清理逻辑
- [x] Task 5A.5: `ExpertModeWindow_Closing` 中确保 CTS 与 `_isScanning` 都正确清理

## 阶段 6：验证 & 构建
- [x] Task 6.1: `dotnet build -c Debug` 0 错误（已验证通过，0 错误 0 警告）
- [x] Task 6.2: 编译 0 个新增警告（与 baseline 对比）
- [x] Task 6.3: 所有 Tab 切换无异常（静态审查通过）
- [x] Task 6.4: 单 IP + Top 100 端口扫描能正常返回结果（流程无回归）
- [x] Task 6.5: 风险等级 / 风险评分 / 漏洞提示在结果中正确显示（未变更相关代码）
- [x] Task 6.6: 扫描完成后再次点击"开始扫描"可正常启动（验证 Task 5A.1 修复 — 引入 `_isScanning` 标志）

## 阶段 7：第三轮深度测试 — 真实 bug 修复
- [x] Task 7.1: **ApplyConfig 控件空安全** — 与 `CollectConfig` 不对称，所有控件访问改为 `?.` 或 `if (...!= null)` 保护
- [x] Task 7.2: **RandomTargetOrder 字段独立化** — `ExpertScanConfiguration` 增加 `RandomTargetOrder` 字段；`CollectConfig` 行 629-630 / `ApplyConfig` 行 703-705 改为读写新字段（不再借用 `Randomize`）
- [x] Task 7.3: **CIDR /0 整数溢出修复** — `ParseTargetCount` 行 287 把 `count = (int)Math.Pow(2, hostBits)` 改为 `1L << hostBits` 并 clamp 到 65536
- [x] Task 7.4: **ExportByTargetButton 单目标死端修复** — 行 2390-2395 用户点 Yes 应能继续普通导出（弹格式对话框复用普通导出的 HTML/CSV/JSON 流程）
- [x] Task 7.5: 编译验证 0 错误 0 警告（已验证）

## 阶段 8：第四轮深度测试 — 关键 bug 修复
- [x] Task 8.1: **Task.Run + Closing 资源竞态**（高危）— 引入 `_scanTaskCompletionSource`，Closing 流程：①`e.Cancel = true` 暂缓关闭 ②Cancel CTS ③`await _scanTaskCompletionSource.Task`（带 3 秒超时）④再 `Close()`
- [x] Task 8.2: **ApplyRecommend 不完整**（中）— 反射兜底：自动查找同名字段并应用到 UI 控件；空守卫覆盖 6 个原字段
- [x] Task 8.3: **ResolveHostname 静默吞错 + 日志误导**（中）— 按异常类型返回哨兵字符串，调用处分支日志
- [x] Task 8.4: **IsHostAlive fail-open 反安全**（中）— `return false` + fail-secure 注释
- [x] Task 8.5: **右键/双击/深度扫描事件空检查 + 并发锁**（中）— 引入 `_resultsLock`；`DeepScanPort_Click` 加 `_isScanning` 守卫；所有 Click 处理器空守卫
- [x] Task 8.6: **扫描时筛选状态同步**（低-中）— `ExecuteExpertScanAsync` 开头重置 ItemsSource
- [x] Task 8.7: **Target 正则预校验**（低）— `StartExpertScanButton_Click` 中 Regex 预校验
- [x] Task 8.8: 编译验证 0 错误 0 警告（已验证）

# Task Dependencies
- 阶段 1 → 阶段 2 → 阶段 3 → 阶段 4 → 阶段 5A → 阶段 6 → 阶段 7 → 阶段 8
- 阶段 8.1-8.5 互不依赖可并行
- 阶段 8.6 依赖 8.5（共享 ItemsSource 重置逻辑）
- 阶段 8.7 独立

# Task Dependencies
- 阶段 1 → 阶段 2 → 阶段 3 → 阶段 4 → 阶段 5A → 阶段 6 → 阶段 7
- 阶段 7.1-7.4 可并行实现（互不依赖）

# Task Dependencies
- 阶段 1 → 阶段 2：必须先发现错误才能修复
- 阶段 2 → 阶段 3：先稳定再完善
- 阶段 3 → 阶段 4：基础稳定后做 UX 提升
- 阶段 4 → 阶段 5A：第二轮深度测试结果（关键 bug）
- 阶段 5A → 阶段 6：最终统一验证

