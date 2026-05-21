# 插件管理功能完善 V2 检查清单

## 命名冲突修复检查
- [x] Plugins.PluginStatus 类已重命名为 PluginRuntimeStatus
- [x] IVulnerabilityScannerPlugin.GetStatus() 返回 PluginRuntimeStatus
- [x] WeakPasswordPlugin.GetStatus() 返回 PluginRuntimeStatus
- [x] PluginManagerWindow 中所有引用已更新为 PluginRuntimeStatus
- [x] Models.PluginStatus 枚举未受影响

## 内置插件检查
- [x] 端口服务识别插件（builtin.portservice）正确加载
- [x] SSL/TLS 检测插件（builtin.ssltls）正确加载
- [x] Web 漏洞扫描插件（builtin.webvuln）正确加载
- [x] 插件管理器列表显示至少 4 个内置插件
- [x] 每个新插件有合理的 ConfigParameters 定义

## 状态持久化检查
- [x] 禁用插件后关闭窗口，重新打开仍为禁用状态
- [x] 启用插件后关闭窗口，重新打开仍为启用状态
- [x] plugin_configs.json 中正确保存 IsEnabled 字段

## 搜索与筛选检查
- [x] 搜索框输入关键词实时过滤插件列表
- [x] 类别筛选下拉框按扫描类型过滤
- [x] "全部"选项重置筛选显示所有插件
- [x] 搜索和筛选可组合使用

## 检查更新检查
- [x] 工具栏有"检查更新"按钮
- [x] 点击后异步检查并显示结果
- [x] 检查过程中按钮禁用防止重复点击

## 配置验证检查
- [x] 必填字段为空时显示错误提示
- [x] Integer 类型输入非数字时显示错误提示
- [x] 验证失败阻止保存

## 日志查看检查
- [x] 插件详情面板有"查看日志"按钮
- [x] 点击后弹出日志窗口
- [x] 日志窗口显示插件运行记录

## PluginMarketWindow 检查
- [x] PluginMarketWindow 使用代码构建 UI（非 XAML）
- [x] 搜索功能正常
- [x] 类别筛选功能正常
- [x] 排序功能正常
- [x] 安装按钮功能正常
- [x] 检查更新功能正常

## 编译检查
- [x] dotnet build 无错误
- [x] 运行程序无崩溃
