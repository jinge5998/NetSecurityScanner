# Tasks

- [x] Task 1: 创建授权码核心模型和工具类
  - [x] SubTask 1.1: 在 NetSecurityScanner.Core/Models/ 创建 LicenseInfo.cs — 授权信息模型（授权类型、到期时间、机器指纹、签发时间、签名等）
  - [x] SubTask 1.2: 在 NetSecurityScanner.Core/Utils/ 创建 MachineFingerprint.cs — 机器指纹生成工具（基于CPU ID、主板序列号、MAC地址组合生成唯一标识）
  - [x] SubTask 1.3: 在 NetSecurityScanner.Core/Utils/ 创建 CryptoHelper.cs — RSA签名验证和AES加解密工具类

- [x] Task 2: 创建授权码服务类
  - [x] SubTask 2.1: 在 NetSecurityScanner.Core/Services/ 创建 LicenseService.cs — 授权码验证、激活、状态查询、持久化存储服务
  - [x] SubTask 2.2: 实现授权码验证逻辑 — RSA签名验证 + AES解密 + 机器指纹匹配 + 有效期检查
  - [x] SubTask 2.3: 实现授权数据持久化 — 加密存储到 %LocalAppData%\NetSecurityScanner\.sys_lic\license.dat
  - [x] SubTask 2.4: 实现授权状态检查方法 — IsLicensed(), GetLicenseStatus(), CheckExpiry()

- [x] Task 3: 创建授权码管理对话框UI
  - [x] SubTask 3.1: 在 NetSecurityScanner.Desktop/Views/ 创建 LicenseDialog.xaml — 授权码管理对话框界面（显示授权状态、输入授权码、激活按钮）
  - [x] SubTask 3.2: 创建 LicenseDialog.xaml.cs — 对话框逻辑（验证授权码、显示状态、激活处理）

- [x] Task 4: 集成授权码功能到主程序
  - [x] SubTask 4.1: 修改 MainWindow.xaml — 在"帮助"菜单中"检查更新"之前添加"授权码"菜单项
  - [x] SubTask 4.2: 修改 MainWindow.xaml.cs — 添加授权码菜单点击事件处理，弹出LicenseDialog
  - [x] SubTask 4.3: 修改 App.xaml.cs — 在OnStartup中添加授权检查，未授权时弹出激活对话框
  - [x] SubTask 4.4: 在主窗口状态栏添加授权状态指示器（显示授权类型和剩余时间）

- [x] Task 5: 创建独立授权码生成器项目
  - [x] SubTask 5.1: 创建 NetSecurityScanner.LicenseGenerator WPF项目 — 新建csproj、App.xaml、MainWindow.xaml
  - [x] SubTask 5.2: 设计生成器UI — 授权类型选择（试用/1年/2年/永久）、生成数量、机器指纹输入（可选）、生成按钮、结果展示、导出功能
  - [x] SubTask 5.3: 实现授权码生成逻辑 — 使用RSA私钥签名 + AES加密，生成Base64编码的授权码
  - [x] SubTask 5.4: 实现批量生成和导出功能 — 批量生成授权码并导出为文本文件
  - [x] SubTask 5.5: 将LicenseGenerator项目添加到解决方案文件

- [x] Task 6: 生成RSA密钥对并嵌入程序
  - [x] SubTask 6.1: 生成RSA-2048密钥对 — 私钥嵌入生成器，公钥嵌入主程序
  - [x] SubTask 6.2: 在主程序LicenseService中嵌入RSA公钥用于验证
  - [x] SubTask 6.3: 在生成器中嵌入RSA私钥用于签名

- [x] Task 7: 编译测试与验证
  - [x] SubTask 7.1: 编译主程序项目，确保无编译错误
  - [x] SubTask 7.2: 编译授权码生成器项目，确保无编译错误
  - [x] SubTask 7.3: 使用生成器生成各类型授权码，在主程序中验证激活流程
  - [x] SubTask 7.4: 验证授权持久化 — 关闭重启程序后授权仍有效
  - [x] SubTask 7.5: 验证机器指纹绑定 — 不同机器指纹无法使用同一授权码

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 2]
- [Task 4] depends on [Task 2, Task 3]
- [Task 5] depends on [Task 1] (共享CryptoHelper和LicenseInfo模型)
- [Task 6] depends on [Task 5]
- [Task 7] depends on [Task 4, Task 6]
