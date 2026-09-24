# 授权码功能增强 Spec

## Why
授权码对话框中的机器码需要一键复制功能方便用户发送给管理员；授权码生成器需要记录发放历史到JSON数据库，支持查询发放时间和到期时间，以及批量导入机器码并批量发放授权码。

## What Changes
- LicenseDialog 中机器码旁增加"复制"按钮，一键复制机器码到剪贴板
- LicenseGenerator 增加发放记录JSON数据库，每次生成授权码自动记录
- LicenseGenerator 增加发放记录查询界面，可按机器码/时间查询
- LicenseGenerator 增加批量导入机器码功能（从文本文件或文本框导入），批量生成并发放

## Impact
- Affected code:
  - `NetSecurityScanner.Desktop/Views/LicenseDialog.xaml` — 增加复制按钮
  - `NetSecurityScanner.Desktop/Views/LicenseDialog.xaml.cs` — 增加复制逻辑
  - `NetSecurityScanner.LicenseGenerator/MainWindow.xaml` — 增加查询和批量导入Tab
  - `NetSecurityScanner.LicenseGenerator/MainWindow.xaml.cs` — 增加查询和批量导入逻辑
  - `NetSecurityScanner.LicenseGenerator/Services/LicenseRecordService.cs` — 新增发放记录服务
  - `NetSecurityScanner.LicenseGenerator/Models/LicenseRecord.cs` — 新增发放记录模型

## ADDED Requirements

### Requirement: 机器码一键复制
系统 SHALL 在授权码对话框的机器码旁提供"复制"按钮。

#### Scenario: 用户复制机器码
- **WHEN** 用户点击机器码旁的"复制"按钮
- **THEN** 机器码被复制到系统剪贴板，按钮文字短暂变为"已复制"提示

### Requirement: 发放记录JSON数据库
系统 SHALL 在授权码生成器中维护一个JSON格式的发放记录数据库。

#### Scenario: 生成授权码时自动记录
- **WHEN** 管理员生成授权码
- **THEN** 系统自动将发放记录保存到 `license_records.json`，包含：授权码、授权类型、机器码、发放时间、到期时间

#### Scenario: 发放记录数据结构
- 每条记录包含：RecordId(string GUID)、LicenseCode(string)、LicenseType(string)、MachineId(string)、IssuedTime(DateTime)、ExpiryTime(DateTime?)、Notes(string)

### Requirement: 发放记录查询
系统 SHALL 在授权码生成器中提供发放记录查询功能。

#### Scenario: 查询所有记录
- **WHEN** 管理员切换到"发放记录"标签页
- **THEN** 显示所有发放记录列表，包含机器码、授权类型、发放时间、到期时间

#### Scenario: 按机器码查询
- **WHEN** 管理员在搜索框输入机器码
- **THEN** 列表过滤显示匹配的发放记录

#### Scenario: 按时间范围查询
- **WHEN** 管理员选择时间范围
- **THEN** 列表过滤显示该时间范围内的发放记录

### Requirement: 批量导入机器码并发放
系统 SHALL 支持批量导入机器码并批量生成授权码。

#### Scenario: 从文本框批量导入
- **WHEN** 管理员在批量导入区域输入多行机器码（每行一个）
- **THEN** 系统为每个机器码生成对应授权码，并记录到发放数据库

#### Scenario: 从文件批量导入
- **WHEN** 管理员点击"导入文件"按钮选择txt文件
- **THEN** 系统读取文件中的机器码列表（每行一个），批量生成授权码

#### Scenario: 批量生成结果展示
- **WHEN** 批量生成完成
- **THEN** 显示每个机器码对应的授权码，可一键复制或导出

## MODIFIED Requirements

### Requirement: 授权码生成器界面
生成器界面从单页面改为TabControl多标签页：
- Tab 1："生成授权码" — 保留现有功能
- Tab 2："批量发放" — 新增批量导入机器码和发放功能
- Tab 3："发放记录" — 新增查询和管理发放记录

## REMOVED Requirements
无
