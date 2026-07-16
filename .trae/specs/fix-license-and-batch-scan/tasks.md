# Tasks

- [x] Task 1: 简化授权码格式 — 重写 LicenseGeneratorService 和 LicenseService
  - [x] SubTask 1.1: CryptoHelper 增加 HMAC-SHA256 生成和验证方法
  - [x] SubTask 1.2: LicensePayload 增加时间戳和类型码字段
  - [x] SubTask 1.3: 重写 LicenseGeneratorService.GenerateLicenseCode — 生成 `硬件码前8位-yyyyMMddHHmmss-类型码-HMAC6位` 格式
  - [x] SubTask 1.4: 重写 LicenseService.ValidateLicenseCode — 解析短码格式并验证 HMAC
  - [x] SubTask 1.5: 更新 LicenseService.ActivateLicense — 适配新验证逻辑
  - [x] SubTask 1.6: 更新 LicenseService.SaveLicense/LoadLicense — 存储新格式授权信息

- [x] Task 2: 优化授权对话框UI — LicenseDialog.xaml/.cs
  - [x] SubTask 2.1: 增大硬件码显示区域，添加一键复制按钮突出显示
  - [x] SubTask 2.2: 授权码输入框适配短码格式，添加格式提示
  - [x] SubTask 2.3: 激活成功后显示授权详情（类型、到期时间）

- [x] Task 3: 优化授权码生成器UI — MainWindow.xaml/.cs
  - [x] SubTask 3.1: 生成标签页 — 硬件码输入框增加粘贴按钮，生成结果格式化显示
  - [x] SubTask 3.2: 批量发放标签页 — 优化机器码列表输入和结果展示
  - [x] SubTask 3.3: 发放记录标签页 — 增加授权码列显示

- [x] Task 4: 重写批量扫描窗口 — BatchScanWindow.xaml/.cs
  - [x] SubTask 4.1: 重写XAML布局 — 左右分栏（左侧IP列表+状态，右侧详细结果）
  - [x] SubTask 4.2: 顶部全局进度区 — 总进度条、已用时间、预计剩余时间、统计数字
  - [x] SubTask 4.3: 左侧IP列表面板 — 每个IP显示状态图标、进度百分比、已用时间
  - [x] SubTask 4.4: 右侧详情面板 — 选中IP的开放端口列表、漏洞列表
  - [x] SubTask 4.5: 底部操作区 — 开始/停止/导出报告按钮
  - [x] SubTask 4.6: 重写扫描逻辑 — 每个IP独立计时、异步并发、实时更新UI
  - [x] SubTask 4.7: 实现报告导出 — HTML和CSV格式

- [x] Task 5: 编译验证 — 确保主程序和生成器均编译通过
  - [x] SubTask 5.1: 编译主程序 NetSecurityScanner.Desktop
  - [x] SubTask 5.2: 编译授权码生成器

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 4] is independent (can parallel with Task 1-3)
- [Task 5] depends on [Task 1, Task 2, Task 3, Task 4]
