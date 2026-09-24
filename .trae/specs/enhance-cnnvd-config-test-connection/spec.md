# 完善 CNNVD 配置：连接测试与即时生效

## Why
上一步已为 CNNVD 增加了数据源地址、API Key、同步间隔、缓存有效期、请求超时等配置项，但用户仍无法验证填写的地址和密钥是否可用，也不清楚配置保存后是否能被同步服务正确读取。因此需要增加一键测试连接能力，并确保配置变更后同步服务即时生效。

## What Changes
- 在 `CnnvdSyncService` 中新增 `TestConnectionAsync` 方法，按用户配置发起连接探测
- `DatabaseSettingsWindow` 中增加“测试连接”按钮及结果反馈区域
- 测试过程禁用按钮，测试完成后给出成功/失败提示（含延迟毫秒数）
- 保存设置后调用 `CnnvdSyncService.ReloadSettings()` 使配置即时生效（已预留，需验证）
- 测试连接不触发完整同步，仅做可达性探测

## Impact
- Affected specs: CNNVD 配置、漏洞库更新
- Affected code: `CnnvdSyncService.cs`, `DatabaseSettingsWindow.xaml`, `DatabaseSettingsWindow.xaml.cs`, `VulnerabilityDatabaseUpdateWindow.xaml.cs`
- No breaking changes

## ADDED Requirements

### Requirement: CNNVD 连接测试
The system SHALL 提供 CNNVD 配置连接测试功能，让用户验证填写的地址、密钥、超时和代理是否可用。

#### Scenario: 测试连接成功
- **WHEN** 用户在 CNNVD 配置面板点击“测试连接”按钮
- **THEN** 系统使用配置的 `BaseUrl`、`RequestTimeoutSeconds`、`UseSystemProxy`、`ApiKey` 发起探测请求
- **AND** 在 1 秒内返回 HTTP 200/204 或成功建立连接
- **AND** 界面显示“连接成功，延迟 xxx ms”

#### Scenario: 测试连接失败
- **WHEN** 用户点击“测试连接”按钮但地址不可达、超时或返回错误
- **THEN** 界面显示“连接失败：错误原因”
- **AND** 按钮在测试期间保持禁用，测试结束后恢复可用

### Requirement: 配置即时生效
The system SHALL 在用户保存 CNNVD 配置后，让 `CnnvdSyncService` 重新加载配置，避免重启程序才能生效。

#### Scenario: 保存配置后生效
- **WHEN** 用户在数据库设置窗口点击“保存”
- **THEN** 设置持久化到 `update_settings.json`
- **AND** 如果主窗口的 `VulnerabilityDatabaseUpdateWindow` 已打开，调用 `CnnvdSyncService.Instance.ReloadSettings()`

## MODIFIED Requirements

### Requirement: CnnvdSyncService 配置读取
**Current**: 服务启动时读取一次 CNNVD 配置，缓存有效期据此生效
**New**: 新增 `TestConnectionAsync` 公共方法，并确保 `ReloadSettings()` 可被 UI 安全调用

### Requirement: DatabaseSettingsWindow CNNVD 配置面板
**Current**: 已包含数据源地址、API Key、同步间隔、缓存有效期、请求超时等输入项
**New**: 在 CNNVD 面板底部增加“测试连接”按钮和结果提示文本

## REMOVED Requirements
无移除需求。
