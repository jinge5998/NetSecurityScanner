# 更新日志 v1.0.3.6

发布日期：2026-11-16

## 概述

对 **RustScan + Nmap + 漏洞扫描** 三引擎进行了针对真实目标 `211.137.75.166`
的深度对比测试（用户自有资产），两引擎端口结果完全一致、漏洞正常检出。
测试中发现并修复了漏洞引擎的 **2 个真实报错**，最终 PASS=10 / FAIL=0、日志零错误。

## 深度测试结果（目标 211.137.75.166）

| 引擎 | 耗时 | 开放端口 | 状态 |
|---|---|---|---|
| RustScan（含服务探测） | ~1.0s | 21, 80, 8098 | ✅ 无 ERROR/WARN |
| Nmap（-sV 服务版本） | ~35s | 21, 80, 8098 | ✅ |
| 双引擎交叉对比 | — | 共同 3 个，各自独有 0 | ✅ 完全一致 |
| 漏洞扫描 | — | 发现 5 条 | ✅ 字段完整 |

检出的漏洞（示例）：

```
[中危] CONFIG-FTP-PLAINTEXT     FTP明文传输          (21/ftp)
[高危] CVE-2023-44487          HTTP/2 Rapid Reset   (80/Microsoft IIS httpd)
[低危] CONFIG-HTTP-PLAINTEXT   HTTP明文Web服务       (80)
[低]   缺失安全头                                   (80, 8098)
```

> 说明：测试中目标端口有波动（首轮 5 个开放端口含 23/8443，复测时 3 个），
> 但每次两引擎结果均完全一致，不影响引擎正确性结论。

## 测试发现并修复的报错

### 1. 漏洞数据库加载报错（首次扫描必现）

**现象**：`Error loading vulnerability database: The JSON value could not be converted to
List<VulnerabilityData>`——随后虽仍显示"已加载 46 条"，但每次扫描都刷一条错误。

**根因（三层）**：
1. `LoadVulnerabilityDatabaseAsync` 只按裸数组 `[...]` 反序列化，而实际文件是
   `{"vulnerabilities":[...]}` 包装对象；
2. 包装字段名有大小写两种：发布包是小写 `vulnerabilities`，
   `%LOCALAPPDATA%\NetSecurityScanner\vulnerability_database.json` 缓存是 `Vulnerabilities`；
3. 该缓存文件还被旧版本写坏——`Vulnerabilities` 元素成了 `{value, Count}` 字典包装，
   即使字段名匹配也无法反序列化。

**修复**：
- 兼容裸数组 / 包装对象两种结构，包装字段名大小写不敏感遍历
- 缓存反序列化失败时**回退发布包 `Data/StaticVulnerabilityDatabase.json`（46 条完整库）**，
  而非回退陈旧的硬编码默认库
- 异常日志降级为 Debug（可自愈异常不应刷 ERROR 给用户）

### 2. HTTPS 端口用 HTTP 探测导致大量超时

**现象**：8443 端口（HTTPS-alt）扫描时刷出 10+ 条
`HTTP error checking sensitive file ... (211.137.75.166:8443)`。

**根因**：`ScanWebServiceAsync` 只把 443 当 HTTPS，8443/9443 等常见 TLS 端口走明文 HTTP。
**修复**：
- HTTPS 端口集合扩展为 `{443, 8443, 9443, 10443}`
- HTTP 客户端加 `ServerCertificateCustomValidationCallback` 容忍自签名证书（扫描场景合理）
- 网络探测失败日志降级为 Debug（目标不可达属预期，不应刷屏）

## 质量验证

| 门禁 | 结果 |
|---|---|
| 三引擎深度测试（真实目标） | **PASS=10 / FAIL=0** |
| 日志清洁度 | 无任何 Error / HTTP error / Exception ✓ |
| 发布产物 | exe / Core.dll = 1.0.3.6，rust + nmap 7.993 + 46 条漏洞库就位 |

## 交付物

| 文件/目录 | 说明 |
|---|---|
| `NetSecurityScanner/publish-v1.0.3.6/` | 主程序发布产物（自带 nmap、rust 引擎、46 条漏洞库） |
