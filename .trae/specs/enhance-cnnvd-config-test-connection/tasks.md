# Tasks

- [x] Task 1: 在 CnnvdSyncService 中实现连接测试方法
  - [x] SubTask 1.1: 新增 `TestConnectionAsync(CancellationToken)` 方法
  - [x] SubTask 1.2: 使用配置的 `BaseUrl`、`RequestTimeoutSeconds`、`UseSystemProxy` 创建 `HttpClient`
  - [x] SubTask 1.3: 若 `ApiKey` 非空，添加 `X-API-Key` 请求头
  - [x] SubTask 1.4: 记录请求耗时，返回 `(bool success, string message, long? latencyMs)`
  - [x] SubTask 1.5: 对网络异常、超时、HTTP 错误码给出友好错误信息

- [x] Task 2: 在 DatabaseSettingsWindow 界面添加测试连接按钮
  - [x] SubTask 2.1: 在 CNNVD 配置面板底部增加 "测试连接" 按钮
  - [x] SubTask 2.2: 增加结果反馈 `TextBlock`（初始为空，成功绿色/失败红色）
  - [x] SubTask 2.3: 点击后禁用按钮并显示 "测试中..."
  - [x] SubTask 2.4: 测试完成后恢复按钮并显示结果

- [x] Task 3: 连接按钮事件与设置保存的即时生效
  - [x] SubTask 3.1: 在 `DatabaseSettingsWindow.xaml.cs` 中实现 `TestConnectionButton_Click`
  - [x] SubTask 3.2: 临时构造 `CnnvdSettings` 或直接用当前控件值调用测试方法
  - [x] SubTask 3.3: 保存设置后调用 `CnnvdSyncService.Instance.ReloadSettings()`（验证已在 `VulnerabilityDatabaseUpdateWindow` 中调用）

- [x] Task 4: 编译与验证
  - [x] SubTask 4.1: `dotnet build NetSecurityScanner.Desktop.csproj` 0 错误
  - [x] SubTask 4.2: 运行程序，打开 CNNVD 配置，点击测试连接观察反馈
  - [x] SubTask 4.3: 修复 `Cnnvd` 属性 JSON 键名大小写，使服务能正确读取 `cnnvd` 节点

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 1, Task 2
- Task 4 depends on Task 1, Task 2, Task 3
