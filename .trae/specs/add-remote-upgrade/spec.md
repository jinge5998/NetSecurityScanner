# 远程软件升级功能规范

## Why
当前软件为本地发行版部署，客户下载后无法获取后续版本更新。需要通过GitHub Releases API实现版本检测，结合百度网盘提供大文件下载渠道，为已安装用户提供便捷的版本升级通道。

## What Changes
- 添加版本检测服务，通过GitHub Releases API获取最新版本信息
- 添加升级包下载服务，支持从百度网盘下载更新包
- 添加升级提示窗口，展示新版本信息与更新日志
- 添加升级配置持久化，支持跳过此版本/不再提醒等选项
- 添加GitHub仓库初始化脚本和Release创建指南

## Impact
- Affected specs: 新增远程升级能力
- Affected code:
  - `NetSecurityScanner.Core/Services/UpdateCheckService.cs` (新建)
  - `NetSecurityScanner.Core/Services/UpdatePackageDownloader.cs` (新建)
  - `NetSecurityScanner.Core/Models/UpdateInfo.cs` (新建)
  - `NetSecurityScanner.Desktop/Views/UpdateDialog.xaml` (新建)
  - `NetSecurityScanner.Desktop/Views/UpdateDialog.xaml.cs` (新建)
  - `NetSecurityScanner.Desktop/MainWindow.xaml` (修改，添加检查更新菜单项)
  - `NetSecurityScanner.Desktop/MainWindow.xaml.cs` (修改，添加检查更新逻辑)
  - `NetSecurityScanner.Desktop/App.xaml.cs` (修改，添加启动时版本检查)

## ADDED Requirements

### Requirement: 版本检测服务
系统 SHALL 提供 `UpdateCheckService` 服务，通过调用 GitHub Releases API 获取最新版本信息。

#### 技术实现
- API端点: `https://api.github.com/repos/{owner}/{repo}/releases/latest`
- 使用 `HttpClient` 发送GET请求，设置合理的User-Agent和超时时间(10秒)
- 解析返回JSON，提取: `tag_name`(版本号)、`published_at`(发布时间)、`body`(更新日志)、`assets`(下载资源列表)
- 使用语义化版本比较( Semantic Versioning )判断是否有新版本可用
- 支持网络超时、API限流(403)、无网络等异常场景的优雅降级

#### 配置项
在 `settings.json` 中添加更新相关配置:
```json
{
  "updateSettings": {
    "githubOwner": "",
    "githubRepo": "NetSecurityScanner",
    "checkOnStartup": true,
    "lastCheckTime": "",
    "skippedVersion": "",
    "notifyInterval": "24h"
  }
}
```

#### Scenario: 成功检测到新版本
- **WHEN** 应用程序启动(或用户手动点击"检查更新")
- **AND** 网络正常且GitHub API可访问
- **AND** 远程版本号大于本地版本号
- **THEN** 弹出升级提示窗口，展示新版本号、发布时间、更新日志
- **AND** 提供"立即下载"、"稍后提醒"、"跳过此版本"三个按钮

#### Scenario: 无新版本可用
- **WHEN** 检测到的最新版本版本号小于等于本地版本
- **THEN** 提示用户"当前已是最新版本"

#### Scenario: 检测失败(网络异常/API限流)
- **WHEN** 版本检测请求超时或返回错误状态码
- **THEN** 静默失败，记录日志，不干扰用户正常使用
- **AND** 手动检查时显示友好错误提示

### Requirement: 升级包下载服务
系统 SHALL 提供 `UpdatePackageDownloader` 服务，支持下载升级包文件。

#### 百度网盘集成
- 百度网盘分享链接: `https://pan.baidu.com/s/17mhsewZVOwTs6c71H5Z-TA?pwd=7cw8`
- 提取码: `7cw8`
- 文件夹名: `NetSecurityScanner升级包`
- 用户在升级窗口点击"下载"后，自动在默认浏览器中打开百度网盘分享链接
- 由于百度网盘无公开下载API，采用浏览器打开方式，由用户手动下载

#### Scenario: 触发下载
- **WHEN** 用户在升级窗口点击"立即下载"按钮
- **THEN** 在系统默认浏览器中打开百度网盘分享链接
- **AND** 窗口显示下载引导提示(包含提取码提示)

### Requirement: 升级提示窗口
系统 SHALL 提供 `UpdateDialog` WPF窗口，用于展示版本更新信息并引导用户操作。

#### 窗口设计要求
- 窗口标题: "发现新版本"
- 窗口尺寸: Width=600, Height=500
- 居中显示，模态窗口(ShowDialog)
- 包含以下信息区域:
  - 新版本号(大号字体，醒目显示)
  - 发布日期
  - 更新日志(Markdown格式渲染，支持列表、代码块等)
  - 当前版本号(对比显示)

#### 操作按钮
- **立即下载**: 打开百度网盘下载链接，关闭窗口
- **稍后提醒**: 关闭窗口，24小时后再次提醒
- **跳过此版本**: 记录跳过的版本号，该版本不再提醒
- 窗口右上角关闭按钮等同于"稍后提醒"

#### 界面样式
- 与项目现有窗口样式保持一致(使用 StyledGroupBox 等已有样式)
- 支持深色/浅色主题
- 更新日志区域使用等宽字体，带滚动条

### Requirement: 启动时版本检查
系统 SHALL 在应用启动时自动检查版本更新(可配置开关)。

#### 检查逻辑
- 在 `App.Startup` 事件中执行异步版本检查
- 检查间隔控制: 距上次检查不足24小时则跳过(手动检查除外)
- 如果用户之前选择了"跳过此版本"且当前最新版本与跳过版本相同，则不弹出提示
- 检查过程不得阻塞主窗口显示
- 使用 `Dispatcher` 确保UI操作在UI线程执行

### Requirement: 手动检查更新
系统 SHALL 在菜单栏提供"检查更新"入口，允许用户随时手动触发版本检查。

#### Scenario: 手动检查
- **WHEN** 用户点击菜单中的"检查更新"
- **THEN** 立即执行版本检测(忽略时间间隔限制)
- **AND** 显示加载状态提示
- **AND** 无论结果如何都给予用户明确反馈

### Requirement: GitHub仓库初始化
提供GitHub仓库初始化脚本和指南，帮助开发者快速创建发布基础设施。

#### 脚本功能
- 初始化本地Git仓库
- 创建 `.gitignore` 文件(排除bin/obj/publish等)
- 创建初始提交
- 推送至远程GitHub仓库
- 创建第一个Release(对应当前版本号)
- 生成Release Notes模板

#### 发布指南
- 如何打包发布文件(`dotnet publish`)
- 如何上传Release附件
- 版本号命名规范(`v1.0.0.2`)
- Release Body格式模板(Markdown)

## MODIFIED Requirements

### Requirement: 主菜单
MainWindow 的"帮助"菜单 SHALL 新增"检查更新"菜单项。

#### 变更内容
在 MainWindow.xaml 的"帮助"菜单中添加:
```xml
<MenuItem Header="帮助">
    ...
    <MenuItem Header="检查更新" Click="CheckForUpdates_Click"/>
</MenuItem>
```

### Requirement: 设置服务
SettingsService SHALL 扩展，支持更新相关配置的读写。

#### 新增配置项
- `UpdateSettings` 类，包含:
  - `GitHubOwner`: GitHub用户名
  - `GitHubRepo`: 仓库名
  - `CheckOnStartup`: 是否启动时检查
  - `LastCheckTime`: 上次检查时间
  - `SkippedVersion`: 跳过的版本号
  - `NotifyInterval`: 提醒间隔(小时)
