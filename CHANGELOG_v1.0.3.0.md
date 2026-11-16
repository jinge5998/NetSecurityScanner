# 更新日志 v1.0.3.0

发布日期：2026-11-15

## 概述

本版本完成 GitHub 版本更新功能的最后接入：帮助菜单新增「🔄 检查更新」入口，
修正自动检查的配置默认值，并交付配套的《GitHub 发布指南》。
更新后已激活软件**无需再次激活**（激活数据与更新文件覆盖范围天然隔离）。

## 主要变更

### 1. 帮助菜单新增「🔄 检查更新」

更新机制的绝大部分能力（GitHub Releases 解析、版本比较、下载/校验/备份/回滚/
pending 延迟替换/自动重启、跳过版本）此前已全部实现，但主窗口帮助菜单只有「关于」，
手动检查更新没有任何入口——用户无法主动触发。

现已在 `帮助 → 🔄 检查更新` 接入现成的 `CheckForUpdates_Click` 处理器：
强制联网检查 → 「发现新版本」弹出 UpdateDialog（版本号/更新说明/下载进度）
或「已是最新版本」提示。

### 2. 修正自动检查的配置默认值（自动提醒生效）

`SettingsService` 默认工厂方法中 `GitHubOwner = ""`（注释提示"必须修改为您的
GitHub 用户名"），导致首次运行生成的 `settings.json` 里 owner 为空，
**启动时的自动检查更新会静默跳过**——与 `UpdateSettings` 模型默认值（`jinge5998`）
不一致。已统一为 `jinge5998`。

自动提醒行为（保持既有实现）：
- 启动时自动检查（默认开启，每 24 小时一次）
- 发现新版本弹出 UpdateDialog，支持"跳过此版本"
- 检查失败静默（不打扰使用）

### 3. 激活状态保留（无需代码改动，已验证隔离性）

| 数据 | 位置 | 更新时处理 |
|---|---|---|
| 激活信息 license.dat | `%LOCALAPPDATA%\NetSecurityScanner\license\` | **不在安装目录，永不触碰**（含机器指纹，AES 加密） |
| 用户设置 settings.json | `%APPDATA%\NetSecurityScanner\` | 不在安装目录 |
| 应用目录 appsettings.json / user-settings.json | 安装目录 | `GitHubAutoUpdater` 明确排除（L503-504/L564） |
| 程序文件（exe/dll/Data） | 安装目录 | 下载→校验→备份→覆盖；被锁定文件转 pending 下次启动替换 |

### 4. 交付《GitHub 发布指南》

`NetSecurityScanner/docs/GitHub发布指南.md`——开发者推送新版本的完整流程：
版本号递增 → 发布打包 → **zip 命名要求**（客户端 `SelectWindowsAsset` 按
`NetSecurityScanner-Desktop/-Windows/-win/NetSecurityScanner/publish` 优先级匹配，
不得含 "Linux"）→ 创建 Release（tag 格式 `vX.Y.Z.Z` 必须与 csproj 一致）→
上传 asset → 用旧版本客户端验证更新推送。含故障排查表。

## 客户端更新链路（最终形态）

```
新版本上传 GitHub Releases（tag vX.Y.Z.Z + zip asset）
  ↓
客户端：启动自动检查（24h 间隔）或「帮助 → 🔄 检查更新」手动触发
  ↓
弹 UpdateDialog（版本号/更新说明/下载进度，支持跳过此版本）
  ↓
下载 zip → 校验 → 备份到 .backup\ → 解压覆盖安装目录
  ↓
运行中锁定文件转 pending → 下次启动自动替换并重启
  ↓
更新完成，激活状态保留，无需重新激活
```

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案 `dotnet build` | 0 错误（退出码 0） |
| 发布产物核对 | exe / Core.dll = 1.0.3.0，rust 引擎 + 46 条漏洞库就位 |
| 启动冒烟 | 主窗口正常显示，`[Update] pending 文件应用结果: 无遗留`，启动链路完整 |

## 建议实测项

1. 主窗口「帮助」菜单 → 应出现「🔄 检查更新」，点击后提示检查结果
   （GitHub 上暂无 Release 时会提示网络/未发布错误，属预期）
2. 按《GitHub 发布指南》发布 v1.0.3.0 Release 后，旧版本（如 1.0.2.9）客户端
   应能检测到并完成自动更新
3. 更新完成后确认无需重新激活

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.0/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
| `NetSecurityScanner/docs/GitHub发布指南.md` | 发布流程 + zip 命名规则 + 故障排查 |
