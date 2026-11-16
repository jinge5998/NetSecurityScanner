# GitHub 版本发布指南（软件更新功能配套）

> 本指南说明如何把新版本发布到 GitHub Releases，使客户端的"🔄 检查更新"功能生效。

## 更新机制总览

客户端已内置完整更新链路（v1.0.3.0 起，帮助菜单可直接触达）：

```
新版本发布到 GitHub Releases
        ↓
客户端启动时自动检查（每 24 小时一次，可关闭）或手动「帮助 → 🔄 检查更新」
        ↓
发现新版本 → 弹出更新对话框（版本号/更新说明/下载进度）
        ↓
下载 zip → 校验 → 备份当前版本到 .backup\时间戳 → 解压覆盖安装目录
        ↓
运行中被锁定的文件（exe/dll）转入 pending 目录，下次启动时完成替换并重启
        ↓
更新完成。激活状态不受影响（license.dat 存于 %LOCALAPPDATA%，不在覆盖范围）
```

**激活保留说明**：激活数据在 `%LOCALAPPDATA%\NetSecurityScanner\license\license.dat`，
更新只覆盖安装目录下的程序文件（且排除 `appsettings.json`、`user-settings.json`），
因此更新后**无需重新激活**。

## 客户端配置（用户侧）

- 检查源：`https://api.github.com/repos/{GitHubOwner}/{GitHubRepo}/releases/latest`
- 默认仓库：`jinge5998/NetSecurityScanner`
- 用户设置文件：`%APPDATA%\NetSecurityScanner\settings.json`
  （`UpdateSettings.CheckOnStartup` 控制启动自动检查，`NotifyIntervalHours` 控制提醒间隔）
- 私有仓库需在 settings.json 中配置 GitHub Token（UpdateCheckService 支持 Authorization 头）

## 发布新版本的操作步骤（开发者侧）

### 1. 更新版本号

四个 csproj 的 `AssemblyVersion/FileVersion/Version` 同步递增：

```
NetSecurityScanner.Desktop / NetSecurityScanner.Core /
NetSecurityScanner / NetSecurityScanner.Linux
```

### 2. 发布并打包

```powershell
# 发布
cd src\NetSecurityScanner.Desktop
dotnet publish -c Release -r win-x64 --self-contained false -o ..\publish-vX.Y.Z.Z

# 复制 Rust 引擎与漏洞库（如未随发布带入）
Copy-Item ..\publish-v旧版本\rust-scanner-service.exe ..\publish-vX.Y.Z.Z\

# 打包（zip 文件名必须含 NetSecurityScanner 或 Desktop/Windows/publish，
# 且不含 "Linux"，客户端据此识别 Windows 包）
Compress-Archive -Path ..\publish-vX.Y.Z.Z\* `
    -DestinationPath NetSecurityScanner-Desktop-vX.Y.Z.Z.zip
```

**Asset 命名要求**（客户端 `SelectWindowsAsset` 按以下优先级匹配 `.zip`）：

| 优先级 | 匹配模式 |
|---|---|
| 1 | `NetSecurityScanner-Desktop`（推荐） |
| 2 | `NetSecurityScanner-Windows` |
| 3 | `NetSecurityScanner-win` |
| 4 | `NetSecurityScanner` |
| 5 | `publish` |

⚠️ 不要在文件名中包含 `Linux`；Linux 版单独发布，使用含 `Linux` 的文件名。

### 3. 创建 GitHub Release

1. 打开仓库 → Releases → Draft a new release
2. **Tag**：`vX.Y.Z.Z`（如 `v1.0.3.0`）——客户端用 tag 与本机版本比较，
   必须与 csproj 版本号一致（格式 `v主.次.修.订`）
3. **标题**：` vX.Y.Z.Z 更新说明`
4. **正文**：粘贴 CHANGELOG 的变更摘要（更新对话框会展示）；
   可附百度网盘备用链接（UpdateCheckService 会解析备用下载源）
5. **上传 asset**：上一步打包的 `NetSecurityScanner-Desktop-vX.Y.Z.Z.zip`
6. 如为预发布版本：勾选 "This is a pre-release"（客户端默认忽略预发布，
   除非用户开启 `CheckPrerelease`）
7. Publish release

### 4. 验证更新推送

- 用旧版本客户端点「帮助 → 🔄 检查更新」→ 应提示发现 vX.Y.Z.Z
- 或启动旧版本客户端（超过 24h 间隔后）→ 自动弹出更新对话框
- 更新流程完成后重启 → 启动日志应显示新版本号且"pending 文件应用结果: 无遗留"

## 故障排查

| 现象 | 排查点 |
|---|---|
| 提示"已是最新版本" | tag 是否严格大于客户端版本（逐段比较，如 v1.0.3.0 > v1.0.2.9） |
| 检查无反应 | `%APPDATA%\NetSecurityScanner\settings.json` 的 GitHubOwner 是否为空（v1.0.3.0 前生成的文件可能为空，需手动填入） |
| 下载失败 | 网络代理/防火墙；私有仓库需配置 Token |
| 更新后部分文件未替换 | 正常现象：被锁定文件进入 pending，下次启动自动完成替换 |
| 更新后需重新激活 | 异常情况——检查 license.dat 是否被误删（正常更新不会触碰） |
