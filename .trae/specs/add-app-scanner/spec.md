# APP扫描功能 Spec

## Why
当前网络安全扫描工具仅支持端口扫描、漏洞扫描和综合扫描功能，缺少对移动应用(APP)的安全扫描能力。根据文档数据，超过70%的移动应用在初步安全检测时就会被发现存在安全隐患。需要添加APP扫描功能以提供针对Android、iOS和小程序应用的安全漏洞检测能力。

## What Changes
- 在扫描菜单栏中添加"APP扫描"菜单项
- 新增APP扫描窗口界面，支持APK/IPA/小程序包上传和扫描
- 实现APP扫描核心服务，集成SAST静态分析能力
- 支持Android APK、iOS IPA、小程序三种类型的扫描
- 提供扫描结果展示和报告导出功能

## Impact
- Affected specs: 扫描功能、用户界面
- Affected code: MainWindow.xaml, AppScannerWindow.xaml, AppScannerService.cs
- 新增文件: AppScannerWindow.xaml, AppScannerWindow.xaml.cs, AppScannerService.cs, AppScanResult.cs

## ADDED Requirements
### Requirement: APP扫描菜单入口
系统SHALL在扫描菜单栏中提供"APP扫描"菜单项，点击后打开APP扫描窗口。

#### Scenario: 打开APP扫描窗口
- **WHEN** 用户点击"扫描 > APP扫描"菜单
- **THEN** 显示APP扫描窗口，包含APK/IPA文件上传、扫描类型选择、扫描结果展示等功能

### Requirement: APP扫描窗口界面
系统SHALL提供完整的APP扫描界面，包含以下元素：
1. 文件选择区域：支持拖拽或点击选择APK/IPA/小程序包
2. 扫描配置区域：选择扫描类型(SAST/DAST/SCA)
3. 扫描进度显示：实时显示扫描进度和日志
4. 扫描结果展示：漏洞列表、风险等级、修复建议

#### Scenario: 选择APP文件
- **WHEN** 用户选择或拖拽APK文件
- **THEN** 界面显示文件信息(名称、大小、类型)，扫描按钮变为可用

### Requirement: APP扫描核心服务
系统SHALL实现AppScannerService，支持以下扫描能力：
1. SAST静态代码分析：检测硬编码密钥、WebView漏洞、权限配置等
2. DAST动态行为分析：分析网络请求、API调用安全性
3. SCA软件成分分析：检测第三方SDK和依赖库漏洞

#### Scenario: 执行APP扫描
- **WHEN** 用户点击"开始扫描"按钮
- **THEN** 系统执行扫描，显示进度条和日志，完成后展示漏洞列表

### Requirement: 扫描结果展示
系统SHALL以表格形式展示扫描结果，包含以下字段：
- 漏洞名称
- 风险等级(高危/中危/低危)
- 漏洞类型
- 所在文件/位置
- CVSS评分
- 修复建议
- 操作(复制详情、标记已处理)

#### Scenario: 查看扫描结果
- **WHEN** 扫描完成
- **THEN** 结果表格显示所有发现的漏洞，按风险等级排序，高危漏洞优先显示

### Requirement: 扫描结果导出
系统SHALL支持将扫描结果导出为Word和PDF格式报告。

#### Scenario: 导出扫描报告
- **WHEN** 用户点击"导出报告"按钮
- **THEN** 弹出文件保存对话框，生成包含完整扫描结果的专业报告

## MODIFIED Requirements
### Requirement: 扫描菜单
**修改**: 在MainWindow.xaml的扫描菜单中添加"APP扫描"菜单项，位置在"开始综合扫描"之后。

## REMOVED Requirements
无
