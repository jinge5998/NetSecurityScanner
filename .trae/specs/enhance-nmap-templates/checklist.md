# Checklist

## 数据模型 (Task 1)
- [ ] `NmapTemplate.cs` 创建在 `Core/Models/`，包含 Id/Name/Icon/Description/NmapCommand/Apply 方法
- [ ] `NmapTemplateRegistry.cs` 内置 19 个模板（14 现有 + 5 新增）
- [ ] `CustomNmapTemplateStore.cs` 实现 JSON 加载/保存

## UI 重构 (Task 2)
- [ ] XAML 中 14 个现有按钮 Click 全部指向 `ApplyNmapTemplateButton_Click`
- [ ] 每个按钮的 Name 携带 Template.Id（如 NmapFastBtn → Id="nmap-fast"）
- [ ] 现有按钮功能完全保留（应用设置 + 弹通知）

## 5 个新模板 (Task 3)
- [ ] Intense Scan 按钮可见且工作
- [ ] Intense Scan Plus UDP 按钮可见且工作
- [ ] Regular Scan 按钮可见且工作
- [ ] Slow Comprehensive Scan 按钮可见且工作
- [ ] Quick Traceroute 按钮可见且工作

## 字段修复 (Task 4)
- [ ] PresetStealthBtn 使用 `RandomTargetOrderCheckBox`（不是 `RandomizeCheckBox`）

## 命令生成增强 (Task 5)
- [ ] `--version-intensity N` 当 ServiceIntensity 设置时
- [ ] `--osscan-limit` 当 OsDetect + TcpScan 时
- [ ] `-Pn` 当 HostDiscovery 关闭时
- [ ] `--open` 可选 flag
- [ ] `--min-rate N` 当 RateLimit 启用时
- [ ] `--stats-every 5s` 进度输出

## 模板预览 (Task 6)
- [ ] "👁️ 预览 nmap 命令" 按钮存在
- [ ] 点击后 TextBox 显示完整命令
- [ ] "📋 复制" 按钮可复制到剪贴板

## 自定义模板 (Task 7)
- [ ] "💾 保存为模板" 按钮弹输入对话框
- [ ] "📂 我的模板" 下拉列出已保存项
- [ ] 加载/删除正常工作
- [ ] 文件保存到 `%LOCALAPPDATA%\NetSecurityScanner\nmap_templates.json`

## Emoji 一致 (Task 8)
- [ ] 所有 19 个模板都有 emoji 前缀

## 验证 (Task 9)
- [ ] `dotnet build` 0 错误 0 新警告
- [ ] 应用启动正常（5 秒内窗口显示）
- [ ] 点击 5 个新模板 → UI 设置正确变化
- [ ] 自定义模板保存→重启应用→仍可见
- [ ] 预览按钮显示完整 nmap 命令
