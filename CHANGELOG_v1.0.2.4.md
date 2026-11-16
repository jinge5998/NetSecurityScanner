# 更新日志 v1.0.2.4

发布日期：2026-10-29

## 概述

本版本在 v1.0.2.3 基础上，主要扩充了内置静态漏洞库内容并完成全系列版本号升级。主程序扫描能力与授权码生成器功能在 v1.0.2.3 基础上保持，重点提升漏洞识别覆盖面。

## 主要变更

### 漏洞库扩充

- 内置静态漏洞库 `StaticVulnerabilityDatabase.json` 条目 **36 → 46 条**，新增 **10 条** 2024-2026 年真实高危/严重 CVE：
  - **CVE-2024-3400** Palo Alto PAN-OS GlobalProtect 命令注入（CVSS 10.0）
  - **CVE-2024-3094** xz Utils 供应链后门 liblzma（CVSS 10.0）
  - **CVE-2024-6387** OpenSSH regreSSHion RCE（CVSS 8.1）
  - **CVE-2024-4577** PHP-CGI 参数注入 RCE（Windows，CVSS 9.8）
  - **CVE-2024-21762** FortiOS SSL VPN 越界写 RCE（CVSS 9.8）
  - **CVE-2024-47575** FortiManager 认证绕过（CVSS 9.8）
  - **CVE-2024-21413** Microsoft Outlook RCE（CVSS 8.8）
  - **CVE-2024-38063** Windows TCP/IP IPv6 RCE（CVSS 9.8）
  - **CVE-2025-0108** PAN-OS 认证绕过（CVSS 7.5）
  - **CVE-2025-26465** OpenSSH 客户端 MITM 认证绕过（CVSS 7.5）
- 每条含：风险分级、CVSS 评分、影响产品、端口/服务、修复方案、官方参考链接、CWE 分类
- 漏洞库版本号 `2024.01` → `2025.06`
- Core / Desktop / 旧 WPF 三处 `StaticVulnerabilityDatabase.json` 保持一致（MD5 相同，均 46 条）

### 版本号升级

- 全系列版本号升级至 1.0.2.4：Core / Desktop / Linux / 旧 WPF / LicenseKeyGenerator 各 csproj 的 `Version`、`AssemblyVersion`、`FileVersion`
- 授权码生成器界面版本显示同步更新（v1.0.2.4）
- 升级渠道保持：GitHub 主升级优先，百度网盘辅助

## 质量验证

- 静态漏洞库 JSON 格式校验通过
- Core / Desktop 项目构建通过（0 错误）
- 新增漏洞数据与库内字段结构完全一致

## 升级方式

1. **GitHub（推荐）**：程序内「检查更新」自动下载 `NetSecurityScanner-Windows-v1.0.2.4.zip` 一键升级
2. **百度网盘**：下载 `NetSecurityScanner-Windows-v1.0.2.4.zip` 解压后覆盖安装目录
3. **升级包目录**：`update-v1.0.2.4/` 与 zip 内容相同，便于手动拷贝

## 交付物清单

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner-Windows-v1.0.2.4.zip` | 主程序发行版（自包含，含 46 条漏洞库） |
| `update-v1.0.2.4/` | 升级包目录（与 zip 内容一致） |
| `LicenseKeyGenerator-v1.0.2.4.zip` | 授权码生成器发行版（自包含） |
| `LicenseKeyGenerator/` | 授权码生成器独立发行文件夹 |
| `NetSecurityScanner/publish-v1.0.2.4/` | 主程序发布产物源目录 |