# 更新日志 v1.0.3.1

发布日期：2026-11-15

## 概述

本版本修复更新检查功能的一个致命 bug，并完成更新功能的端到端实测验证。

## 修复明细

### 1. 更新检查 JSON 解析永远失败（致命 bug，测试中发现）

对更新功能做端到端实测时发现：`UpdateCheckService` 调用 GitHub API 成功，
但 **JSON 反序列化永远失败**——`GitHubReleaseResponse` / `GitHubAsset` 模型类
没有任何 `[JsonPropertyName]` 特性，而 GitHub API 返回 snake_case 键
（`tag_name` / `html_url` / `browser_download_url` / `published_at`），
反序列化选项只有 `PropertyNameCaseInsensitive`（大小写不敏感 ≠ 命名策略转换），
`TagName` 恒为 null → 「解析远程更新信息失败」→ 返回 null。

**后果**：更新检查功能在此修复前从未可能成功（客户端永远提示"已是最新"或静默跳过）。

**修复**：补齐全部 snake_case 映射特性，端到端实测通过（详见下表）。

## 更新功能端到端实测结果（真实 GitHub API）

| 用例 | 结果 |
|---|---|
| 以 v1.0.2.9 身份检查 → 发现 v1.0.3.0 | PASS |
| 更新信息字段（版本号 / asset 选中 / 命名规则） | PASS × 3 |
| 以 v1.0.3.0 身份检查 → 已是最新 | PASS |
| 安装包真实下载（HTTP 200 / 18.9MB / zip 文件头 PK 校验） | PASS × 2 |
| **合计** | **PASS=7 / FAIL=0** |

## 质量验证

| 门禁 | 结果 |
|---|---|
| 全解决方案构建 | 0 错误 |
| NetSecurityScanner.Core.Tests | **305/305 通过** |
| 发布产物核对 | exe / Core.dll = 1.0.3.1，rust 引擎 + 46 条漏洞库就位 |
| GitHub Release v1.0.3.1 | 已推送，asset `NetSecurityScanner-Desktop-v1.0.3.1.zip`（18 MB） |

## 注意事项

- v1.0.3.0 Release 的安装包内含带解析 bug 的 Core.dll（更新检查无法工作）。
  **请以本版本（v1.0.3.1）为起点**：旧版本客户端（含 v1.0.3.0）通过「帮助 → 检查更新」
  下载 v1.0.3.1 后，后续所有版本检查均正常。
- 更新完成后激活状态保留，无需重新激活。

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.1/` | 主程序发布产物（含 rust-scanner-service.exe、46 条漏洞库） |
| `https://github.com/jinge5998/NetSecurityScanner/releases/tag/v1.0.3.1` | GitHub Release |
