# 更新日志 v1.0.3.5

发布日期：2026-11-16

## 概述

对 Nmap 引擎进行了**深度自动化测试**（42 项用例，真实调用 nmap 7.993），
发现并修复 2 个真实缺陷，最终 **PASS=42 / FAIL=0**。

## 深度测试覆盖范围（42 项）

| 类别 | 用例数 | 内容 |
|---|---|---|
| 环境与定位 | 3 | nmap.exe 定位、版本读取、版本格式 |
| 命令生成 | 12 | 端口模式（All/Sensitive/Custom）、Stealth/T2、SynScan/-sS、OS/服务检测、排除端口/主机、多输出格式 |
| 真实扫描 | 4 | 开放/关闭端口识别、结果条数、TargetIp 回填 |
| 服务探测 | 2 | -sV 触发 NSE 引擎、结果完整性 |
| 配置组合 | 8 | Verbosity、ReverseDns、RateLimit、RandomPortOrder、ExcludePorts、多输出格式、ShowOpenOnly、PingProbe |
| 边界情况 | 3 | 空端口列表、无效目标、200 端口批量扫描 |
| 取消支持 | 1 | CancellationToken 响应（全端口扫描场景） |
| XML 解析 | 5 | open/filtered/closed 状态、产品版本解析、非法 XML |
| 结果字段 | 4 | TargetIp / PortNumber / Status / Confidence 完整性 |

## 测试发现并修复的真实缺陷

### 1. `--randomize-ports` 是 nmap 不存在的非法参数

`NmapCommandBuilder` 在用户勾选「随机端口顺序」时输出 `--randomize-ports`，
但 nmap 7.993 报 `unrecognized option '--randomize-ports'` 并退出——**该配置组合下
整次扫描返回 0 条结果**。

**修复**：
- Builder 不再输出该非法参数（nmap 端口顺序本来就是随机的，`-r` 才是顺序扫描）
- `ScanAsync` 参数清洗同步剥离该 token（兼容用户旧配置/复制的旧命令）

### 2. 大端口集超出 Windows 命令行长度限制

取消测试中 65535 个端口拼成 `-p 1,2,3,...`（约 300KB），超过 Windows
CreateProcess 的 ~32767 字符限制，nmap 进程无法启动（报"文件名或扩展名太长"）。
**全端口扫描在旧版本必然失败**。

**修复**：新增 `CompressPortRanges()`，把连续端口压缩为区间格式：
`[1,2,3,5,80,443,444]` → `1-3,5,80,443-444`；全端口压缩为 `1-65535`，
命令行长度恒定，nmap 完全支持。

### 3. 测试断言修正（非产品缺陷）

- 版本号正则原按 3 段数字匹配，nmap 7.993 是 2 段 → 断言改为兼容 2/3 段
- StealthMode 语义是降速至 `-T2`（非 SYN），SYN 由 `SynScan` 控制 → 断言拆分为两项独立验证

## 质量验证

| 门禁 | 结果 |
|---|---|
| 深度测试（真实 nmap） | **PASS=42 / FAIL=0** |
| 发布产物 | exe / Core.dll = 1.0.3.5，rust + nmap 7.993 + 46 条漏洞库就位 |

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.5/` | 主程序发布产物（自带 nmap 7.993、rust 引擎、46 条漏洞库） |
