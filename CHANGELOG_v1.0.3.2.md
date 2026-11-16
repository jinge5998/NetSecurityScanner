# 更新日志 v1.0.3.2

发布日期：2026-11-15

## 概述

对版本更新功能做**全链路端到端实测**（真实下载安装到隔离沙箱），确认更新链路本身
正常，但发现国内网络环境下 `github.com:443` 直连不稳定导致 asset 下载失败。
本版本为下载链路增加**镜像自动回退**，并经沙箱 E2E 实测验证完整更新流程成功。

## E2E 实测发现的问题与修复

### 1. asset 下载在直连 GitHub 失败时无替代路径（已修复）

沙箱实测过程（真实下载 18MB 安装包 → 校验 → 解压 → 备份 → 覆盖）中，
首次直连下载 3 次重试全部失败：
`由于连接方在一段时间后没有正确答复或连接的主机没有反应，连接尝试失败 (github.com:443)`
——与 git push 被阻断是同一网络环境问题。更新链路代码本身工作正常
（检查更新、asset 选中、下载重试、**失败自动回滚**均验证通过）。

**修复**：下载候选自动回退链：

```
用户配置镜像（settings.json → DownloadProxyPrefix，可选）
  → 原始 URL（github.com）
    → gh-proxy.com → ghfast.top → mirror.ghproxy.com（内置公共镜像）
```

某一候选失败自动切换下一个，全部失败才计入重试失败。用户网络若有稳定镜像，
可在 `%APPDATA%\NetSecurityScanner\settings.json` 的
`UpdateSettings.DownloadProxyPrefix` 填入（如 `https://gh-proxy.com/`）。

**沙箱实测结果**：直连失败 → 镜像下载成功（18MB 完整）→ 解压覆盖 →
沙箱内 `NetSecurityScanner.Desktop.exe` 版本变为 1.0.3.1、漏洞库就位、
`.backup` 生成、用户配置保留（模拟激活保留验证）——**全链路成功**。

## 确认正常的更新链路（本轮验证）

| 环节 | 验证方式 | 结果 |
|---|---|---|
| 版本检查（GitHub Releases API） | 以 1.0.2.9 身份真实调用 | ✅ 发现 v1.0.3.1 |
| asset 识别（命名规则匹配） | SelectWindowsAsset | ✅ 正确选中 zip |
| 已是最新判定 | 以 1.0.3.1 身份调用 | ✅ 无更新 |
| 下载（含镜像回退） | 沙箱真实下载 18MB | ✅ 镜像成功 |
| 完整性校验（SHA256/长度） | DownloadAndInstallAsync | ✅ |
| 解压 → 备份 → 覆盖 | 沙箱实测 | ✅ |
| **失败回滚** | 人为网络阻断触发 | ✅ 自动回滚，安装目录完好 |
| 用户配置/激活保留 | 沙箱 user-settings 等价验证 | ✅ 未触碰 |

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案构建 | 0 错误 |
| NetSecurityScanner.Core.Tests | **305/305 通过** |
| 发布产物核对 | exe / Core.dll = 1.0.3.2，rust 引擎 + 46 条漏洞库就位 |

## 注意事项

- v1.0.3.1 Release 的安装包不含镜像回退（直连 GitHub 失败的网络无法自动更新）。
  建议以本版本（v1.0.3.2）为分发起点。
- 内置镜像为公共服务，可用性随时间变化；全部失败时用户可自行配置
  `DownloadProxyPrefix` 或开代理后重试。

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.2/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
| `https://github.com/jinge5998/NetSecurityScanner/releases/tag/v1.0.3.2` | GitHub Release（18 MB zip） |
