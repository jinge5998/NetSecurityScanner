# 授权码功能 Spec

## Why
软件需要授权激活才能使用，防止未授权使用。通过授权码机制控制软件使用权限，支持试用版（5分钟）、1年期、2年期和永久使用四种授权类型，同时提供独立的授权码生成器工具方便管理员生成授权码。

## What Changes
- 在"帮助"菜单中增加"授权码"菜单项，点击弹出授权码管理对话框
- 应用启动时检查授权状态，未授权或授权过期则限制使用并提示激活
- 创建 `LicenseService` 服务类，负责授权码的验证、存储和状态管理
- 创建 `LicenseGenerator` 独立WPF项目，作为授权码生成器（单机版）
- 授权码采用RSA签名 + AES加密机制，防止伪造和篡改
- 激活的授权码自动存入隐藏的加密JSON文件中，软件更新不影响授权
- 授权码与机器指纹绑定，防止一码多用

## Impact
- Affected specs: 应用启动流程、帮助菜单
- Affected code:
  - `NetSecurityScanner.Desktop/App.xaml.cs` — 启动时增加授权检查
  - `NetSecurityScanner.Desktop/MainWindow.xaml` — 帮助菜单增加"授权码"项
  - `NetSecurityScanner.Desktop/MainWindow.xaml.cs` — 增加授权码菜单点击处理
  - `NetSecurityScanner.Core/Services/` — 新增 `LicenseService.cs`
  - `NetSecurityScanner.Core/Models/` — 新增 `LicenseInfo.cs`
  - `NetSecurityScanner.Core/Utils/` — 新增 `MachineFingerprint.cs`
  - `NetSecurityScanner.LicenseGenerator/` — 新增独立授权码生成器项目

## ADDED Requirements

### Requirement: 授权码管理对话框
系统 SHALL 在"帮助"菜单下提供"授权码"菜单项，点击后弹出授权码管理对话框，显示当前授权状态并允许输入新授权码。

#### Scenario: 已授权用户查看授权状态
- **WHEN** 用户点击"帮助"→"授权码"
- **THEN** 弹出对话框显示当前授权类型、到期时间、机器指纹等信息

#### Scenario: 未授权用户输入授权码
- **WHEN** 用户在授权码对话框中输入授权码并点击"激活"
- **THEN** 系统验证授权码有效性，验证通过后激活软件并显示成功提示；验证失败则显示错误原因

#### Scenario: 授权过期用户
- **WHEN** 用户授权已过期
- **THEN** 对话框显示"授权已过期"状态，用户可输入新授权码重新激活

### Requirement: 启动时授权检查
系统 SHALL 在应用启动时自动检查授权状态。

#### Scenario: 首次启动（未授权）
- **WHEN** 应用首次启动且无有效授权
- **THEN** 自动弹出授权码激活对话框，用户必须激活才能使用软件

#### Scenario: 试用版过期
- **WHEN** 试用版授权（5分钟）已过期
- **THEN** 弹出提示"试用已过期"，要求输入正式授权码

#### Scenario: 有效授权启动
- **WHEN** 应用启动时存在有效授权
- **THEN** 正常进入软件，不弹出授权对话框

### Requirement: 授权码类型
系统 SHALL 支持以下四种授权类型：

| 类型 | 编码 | 有效期 | 说明 |
|------|------|--------|------|
| 试用版 | TRIAL | 5分钟 | 从激活时刻起5分钟 |
| 1年期 | YEAR1 | 1年 | 从激活时刻起1年 |
| 2年期 | YEAR2 | 2年 | 从激活时刻起2年 |
| 永久版 | PERMANENT | 永久 | 无到期时间 |

#### Scenario: 试用版倒计时
- **WHEN** 用户激活试用版授权码
- **THEN** 软件可使用5分钟，状态栏显示剩余时间倒计时

#### Scenario: 1年期授权
- **WHEN** 用户激活1年期授权码
- **THEN** 软件可使用1年，到期前一天弹出续期提醒

### Requirement: 授权码加密与防篡改
系统 SHALL 使用RSA签名和AES加密保护授权码。

#### Scenario: 授权码验证
- **WHEN** 用户输入授权码
- **THEN** 系统使用内置RSA公钥验证签名，验证数据完整性，解密授权信息

#### Scenario: 防止伪造授权码
- **WHEN** 用户输入伪造的授权码
- **THEN** 系统RSA签名验证失败，拒绝激活并提示"无效的授权码"

### Requirement: 机器指纹绑定
系统 SHALL 将授权码与当前机器的硬件指纹绑定。

#### Scenario: 同一授权码在同一机器使用
- **WHEN** 用户在同一台机器上重新输入已激活的授权码
- **THEN** 系统识别为同一机器，正常激活

#### Scenario: 同一授权码在不同机器使用
- **WHEN** 用户尝试在不同机器上使用已绑定其他机器的授权码
- **THEN** 系统提示"此授权码已绑定其他设备，无法在此设备使用"

### Requirement: 授权数据持久化
系统 SHALL 将激活的授权信息存储在隐藏的加密JSON文件中。

#### Scenario: 授权数据存储
- **WHEN** 用户成功激活授权码
- **THEN** 系统将授权信息加密后存储到 `%LocalAppData%\NetSecurityScanner\.sys_lic\license.dat`

#### Scenario: 软件更新不影响授权
- **WHEN** 软件从旧版本更新到新版本
- **THEN** 授权文件位于用户数据目录，不受软件安装目录更新影响，授权保持有效

#### Scenario: 授权文件隐藏
- **WHEN** 用户浏览文件系统
- **THEN** 授权文件存储在 `.sys_lic` 隐藏目录中，文件内容为AES加密的二进制数据，无法直接阅读或篡改

### Requirement: 独立授权码生成器
系统 SHALL 提供独立的授权码生成器工具（NetSecurityScanner.LicenseGenerator），作为单独的WPF应用程序。

#### Scenario: 管理员生成授权码
- **WHEN** 管理员打开授权码生成器，选择授权类型，点击"生成"
- **THEN** 系统使用RSA私钥签名生成授权码，显示在界面上，可复制

#### Scenario: 批量生成授权码
- **WHEN** 管理员选择授权类型并设置生成数量
- **THEN** 系统批量生成指定数量的授权码，可导出为文本文件

#### Scenario: 授权码生成器独立性
- **WHEN** 管理员使用授权码生成器
- **THEN** 生成器为独立可执行文件，不依赖主程序安装，可单独运行

### Requirement: 授权码格式
授权码 SHALL 采用以下格式规范：

- 授权码为Base64编码字符串，长度约128-256字符
- 内部数据结构（JSON）：`{ "type": "YEAR1", "issued": "2026-05-22T10:00:00Z", "machineId": "XXXX", "signature": "..." }`
- RSA-2048签名确保不可伪造
- AES-256加密确保内容不可读取

## MODIFIED Requirements

### Requirement: 帮助菜单
在现有"帮助"菜单（包含"检查更新"和"关于"）中，在"检查更新"之前增加"授权码"菜单项。

### Requirement: 应用启动流程
应用启动时（App.xaml.cs OnStartup），在现有更新检查之前，先执行授权状态检查。未授权时阻止主窗口正常使用。

## REMOVED Requirements
无移除的需求。
