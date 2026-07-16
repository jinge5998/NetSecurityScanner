# IPv6与域名扫描功能增强 Spec

## Why
当前网络安全扫描工具主要支持IPv4地址扫描。随着IPv6网络的普及和域名解析需求的增长，需要扩展扫描工具以支持IPv6地址扫描、域名扫描以及提供独立的域名解析功能。

## What Changes
- 为端口扫描服务增加IPv6地址支持（支持TCP/UDP）
- 为漏洞扫描服务增加IPv6地址支持
- 增加域名扫描功能（自动解析域名到IP地址并执行扫描）
- 在工具栏增加独立的域名解析功能按钮

## Impact
- Affected code: PortScanner.cs, VulnerabilityScanner.cs, TargetValidationService.cs, MainWindow.xaml/cs
- Affected UI: 端口扫描Tab、漏洞扫描Tab、工具栏

## ADDED Requirements

### Requirement: IPv6端口扫描支持
系统 SHALL 支持使用IPv6地址进行TCP和UDP端口扫描：
- 在目标IP输入框中识别IPv6格式（如 2001:db8::1）
- 使用 System.Net.Sockets.TcpClient 连接IPv6地址（AddressFamily.InterNetworkV6）
- UDP扫描同样支持IPv6地址
- 显示结果时保留IPv6地址格式

#### Scenario: 使用IPv6地址进行TCP端口扫描
- **WHEN** 用户在目标IP输入框中输入 IPv6地址（如 fe80::1）
- **THEN** 系统识别为IPv6地址，使用IPv6协议进行端口扫描

#### Scenario: 使用IPv6地址进行UDP端口扫描
- **WHEN** 用户选择UDP扫描并输入IPv6地址
- **THEN** 系统使用IPv6地址执行UDP端口扫描

### Requirement: IPv6漏洞扫描支持
系统 SHALL 支持使用IPv6地址进行漏洞扫描：
- 在扫描漏洞前识别目标地址类型（IPv4/IPv6）
- 对于IPv6目标，调整Socket连接参数使用IPv6协议
- HTTP漏洞检测支持通过IPv6地址访问

#### Scenario: IPv6目标漏洞扫描
- **WHEN** 用户对IPv6地址执行漏洞扫描
- **THEN** 系统使用IPv6协议连接目标端口并执行漏洞检测

### Requirement: 域名扫描功能
系统 SHALL 支持直接输入域名进行扫描：
- 用户可以输入域名（如 example.com）作为扫描目标
- 系统自动解析域名获取所有关联的IP地址（IPv4和IPv6）
- 对解析到的每个IP地址执行端口扫描和漏洞扫描
- 扫描结果中显示域名和解析到的IP地址

#### Scenario: 域名扫描全流程
- **WHEN** 用户在目标输入框中输入域名 example.com
- **THEN** 系统解析域名为IP地址列表，对每个IP执行扫描

#### Scenario: 域名解析失败
- **WHEN** 用户输入的域名无法解析
- **THEN** 系统显示解析错误提示，扫描终止

### Requirement: 工具栏域名解析功能
系统 SHALL 提供独立的域名解析工具按钮：
- 在工具栏添加"域名解析"按钮
- 点击按钮弹出域名解析对话框
- 支持将域名解析为IPv4和IPv6地址
- 显示多个解析结果（如有）
- 提供复制IP地址功能

#### Scenario: 点击域名解析按钮
- **WHEN** 用户点击工具栏的"域名解析"按钮
- **THEN** 弹出域名解析对话框

#### Scenario: 域名解析成功
- **WHEN** 用户输入有效域名并点击解析
- **THEN** 显示所有解析到的IP地址（IPv4和IPv6）

#### Scenario: 域名解析失败
- **WHEN** 用户输入无效域名或DNS解析失败
- **THEN** 显示错误提示信息

## MODIFIED Requirements

### Requirement: 目标输入验证
原实现：仅支持IPv4地址验证
新实现：
- 支持IPv4地址验证（192.168.1.1）
- 支持IPv6地址验证（2001:db8::1）
- 支持域名验证（www.example.com）
- 支持CIDR网段验证（192.168.1.0/24）

### Requirement: 端口扫描输入标签
原标签：目标IP/域名
新标签：目标IP/域名/IPv6
更新提示信息以包含IPv6示例

## REMOVED Requirements
无
