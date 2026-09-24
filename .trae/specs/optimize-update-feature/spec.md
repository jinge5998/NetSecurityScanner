# Optimize Update Feature Spec

## Why
当前版本更新功能通过 GitHub Release API 获取最新版本信息，并从 release notes 中提取百度网盘下载链接和提取码。但存在以下问题需要优化：
- GitHub 仓库 README 和 Release 内容需要同步更新
- 更新对话框提取百度网盘信息的正则表达式需要增强
- 缺少更新包的版本号校验机制

## What Changes
- 增强 GitHub Release 内容格式规范，便于自动解析百度网盘链接和提取码
- 优化更新对话框 UI，提供更清晰的下载指引
- 确保 GitHub Release 的 body 中包含标准格式的百度网盘下载信息
- 优化 `ParseBaiduDownloadInfo` 方法，支持更多格式的百度网盘链接和提取码
- 增强更新检查服务的容错能力

## Impact
- Affected specs: 版本更新检查、远程更新下载
- Affected code: UpdateCheckService.cs, UpdateDialog.xaml, UpdateDialog.xaml.cs, README.md
- GitHub Release body 格式规范化

## ADDED Requirements
### Requirement: GitHub Release Content Format
GitHub Release 的 Body 必须包含以下标准格式内容，便于客户端自动解析：

```
## 下载方式

百度网盘下载：https://pan.baidu.com/s/17mhsewZVOwTs6c71H5Z-TA?pwd=7cw8
提取码：7cw8

## 更新说明
- 新增：xxx功能
- 修复：xxx问题
```

#### Scenario: Client auto-extracts download info
- **WHEN** client fetches GitHub Release info via API
- **THEN** it should automatically parse Baidu download URL and extraction code from release body
- **AND** display them in the update dialog

### Requirement: Enhanced Update Dialog
The update dialog shall provide:
1. Clear version comparison (current vs latest)
2. Prominent Baidu Netdisk download link (clickable)
3. Extraction code with one-click copy button
4. Detailed release notes in scrollable area
5. Three action buttons: Download, Remind Later, Skip

#### Scenario: User clicks download
- **WHEN** user clicks "立即下载" button
- **THEN** browser opens the Baidu Netdisk download link
- **AND** the dialog closes

#### Scenario: User copies extraction code
- **WHEN** user clicks "复制" button next to extraction code
- **THEN** the code is copied to clipboard
- **AND** button text changes to "已复制" for 2 seconds

### Requirement: Release Notes Parsing Enhancement
The `ParseBaiduDownloadInfo` method shall support multiple formats:

```csharp
// Supported formats for Baidu URL:
// 1. https://pan.baidu.com/s/xxxxxx?pwd=xxxx
// 2. 链接：https://pan.baidu.com/s/xxxxxx 提取码：xxxx
// 3. 百度网盘：https://pan.baidu.com/s/xxxxxx 密码：xxxx
// 4. 下载链接: https://pan.baidu.com/s/xxxxxx
// 5. https://pan.baidu.com/s/xxxxxx (no pwd in URL)

// Supported formats for extraction code:
// 1. 提取码：xxxx
// 2. 密码：xxxx
// 3. 提取码: xxxx
// 4. ?pwd=xxxx (in URL)
```

## MODIFIED Requirements
### Requirement: UpdateCheckService.ParseBaiduDownloadInfo
**Current**: Only matches `https://pan.baidu.com/s/[^\s\)]+` and `提取码[：:]\s*(\w{4})`
**New**: Support multiple formats including password in URL (`?pwd=xxxx`) and various text patterns

### Requirement: UpdateDialog Display
**Current**: Shows Baidu URL as clickable text
**New**: Add "📥 点击打开百度网盘链接" prompt text for better UX

## REMOVED Requirements
None
