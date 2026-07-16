# 授权码简化与批量扫描完善 Spec

## Why
当前授权码使用 RSA-2048签名 + AES-256加密 + Base64编码，生成的授权码过长且复杂，用户难以使用；授权流程不够直观。批量扫描功能存在卡顿、无时间显示、页面显示不全、IP列表缺少独立进度等问题。

## What Changes
- 简化授权码格式为：`硬件码前8位-生成时间-授权类型-HMAC校验码`，保留安全性但大幅缩短长度
- 统一主程序与生成器的授权码编解码逻辑
- 优化授权流程：主程序复制硬件码 → 生成器粘贴硬件码生成授权码 → 主程序激活
- 重写批量扫描窗口，增加每个IP独立进度、实时时间显示、完整结果统计、报告导出
- **BREAKING**: 授权码格式变更，旧授权码将失效

## Impact
- Affected specs: add-license-authorization, enhance-license-generator, add-comprehensive-scan
- Affected code:
  - NetSecurityScanner.Core/Models/LicenseInfo.cs — LicensePayload 增加字段
  - NetSecurityScanner.Core/Services/LicenseService.cs — 重写验证逻辑
  - NetSecurityScanner.Core/Utils/CryptoHelper.cs — 增加 HMAC-SHA256 方法
  - NetSecurityScanner.Desktop/Views/LicenseDialog.xaml/.cs — 优化授权流程UI
  - 授权码生成器/LicenseGeneratorService.cs — 重写生成逻辑
  - 授权码生成器/MainWindow.xaml/.cs — 优化生成器UI
  - NetSecurityScanner.Desktop/Views/BatchScanWindow.xaml/.cs — 重写批量扫描

## ADDED Requirements

### Requirement: 简化授权码格式
系统 SHALL 生成格式为 `{硬件码前8位}-{yyyyMMddHHmmss}-{类型码}-{HMAC6位校验}` 的授权码。

#### Scenario: 生成授权码
- **WHEN** 用户在生成器中选择授权类型并输入硬件码
- **THEN** 生成格式如 `A1B2C3D4-20260522143000-P-3F8A2B` 的授权码
- **AND** 类型码为 T(试用)/1(1年)/2(2年)/P(永久)

#### Scenario: 验证授权码
- **WHEN** 用户在主程序中输入授权码
- **THEN** 系统解析授权码各段，验证HMAC校验码
- **AND** 验证硬件码匹配当前机器（如绑定）
- **AND** 验证授权类型和到期时间

### Requirement: 优化授权流程
系统 SHALL 提供直观的授权激活流程。

#### Scenario: 复制硬件码
- **WHEN** 用户打开授权对话框
- **THEN** 显示硬件码和一键复制按钮
- **AND** 硬件码以32位十六进制格式显示

#### Scenario: 激活授权
- **WHEN** 用户粘贴授权码并点击激活
- **THEN** 系统验证授权码有效性
- **AND** 显示激活成功/失败原因

### Requirement: 批量扫描IP列表管理
系统 SHALL 在批量扫描中显示所有IP列表及每个IP的独立状态。

#### Scenario: 显示IP列表
- **WHEN** 用户解析目标后开始扫描
- **THEN** 左侧面板显示所有IP列表，每个IP显示独立状态（等待中/扫描中/已完成/失败）
- **AND** 每个IP显示扫描进度百分比和已用时间

#### Scenario: 点击IP查看详情
- **WHEN** 用户点击某个IP
- **THEN** 右侧面板显示该IP的详细扫描结果（开放端口、漏洞列表）

### Requirement: 批量扫描实时统计
系统 SHALL 实时显示扫描统计信息。

#### Scenario: 扫描进行中
- **WHEN** 批量扫描正在执行
- **THEN** 顶部显示：总目标数、已完成数、失败数、总漏洞数、严重漏洞数
- **AND** 显示总已用时间和预计剩余时间
- **AND** 进度条实时更新

### Requirement: 批量扫描报告导出
系统 SHALL 支持导出批量扫描报告。

#### Scenario: 导出HTML报告
- **WHEN** 用户点击导出报告
- **THEN** 生成包含所有IP扫描结果的HTML报告
- **AND** 报告包含概要统计和每个IP的详细结果

#### Scenario: 导出CSV报告
- **WHEN** 用户选择CSV格式导出
- **THEN** 生成CSV文件包含所有IP的扫描摘要

## MODIFIED Requirements

### Requirement: 授权码编解码统一
主程序和生成器 SHALL 使用相同的授权码格式和编解码逻辑。授权码格式从 RSA+AES+Base64 改为 HMAC-SHA256 校验的短码格式。

### Requirement: 批量扫描窗口重写
批量扫描窗口 SHALL 使用左右分栏布局：左侧IP列表+状态，右侧选中IP的详细结果。顶部显示全局进度和统计，底部显示操作按钮。

## REMOVED Requirements

### Requirement: RSA-2048签名授权码
**Reason**: 授权码过长（数百字符），用户难以复制和使用，改为HMAC校验的短码格式
**Migration**: 旧授权码将失效，需使用新生成器重新生成
