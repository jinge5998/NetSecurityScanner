# Tasks

- [x] Task 1: 修改 PortScanner 支持IPv6扫描
  - [x] SubTask 1.1: 修改 ScanTcpPortAsync 方法，检测目标地址类型
  - [x] SubTask 1.2: 使用 TcpClient(AddressFamily.InterNetworkV6) 连接IPv6地址
  - [x] SubTask 1.3: 修改 ScanUdpPortAsync 方法支持IPv6
  - [x] SubTask 1.4: 修改服务版本识别支持IPv6连接

- [x] Task 2: 修改 VulnerabilityScanner 支持IPv6扫描
  - [x] SubTask 2.1: 在扫描方法中检测目标地址类型
  - [x] SubTask 2.2: 调整Socket连接使用IPv6协议
  - [x] SubTask 2.3: HTTP漏洞检测支持IPv6 URL

- [x] Task 3: 实现域名扫描功能
  - [x] SubTask 3.1: 在 MainWindow.xaml.cs 添加域名扫描处理方法
  - [x] SubTask 3.2: 使用 Dns.GetHostAddressesAsync 解析域名
  - [x] SubTask 3.3: 对解析到的每个IP地址执行扫描
  - [x] SubTask 3.4: 在结果中显示域名信息

- [x] Task 4: 创建域名解析对话框
  - [x] SubTask 4.1: 创建 DnsResolverWindow.xaml 窗口
  - [x] SubTask 4.2: 实现域名解析逻辑（支持IPv4/IPv6）
  - [x] SubTask 4.3: 显示解析结果列表
  - [x] SubTask 4.4: 添加复制IP地址功能

- [x] Task 5: 在工具栏添加域名解析按钮
  - [x] SubTask 5.1: 在 MainWindow.xaml 菜单栏后添加工具栏
  - [x] SubTask 5.2: 添加"域名解析"按钮
  - [x] SubTask 5.3: 绑定按钮点击事件打开域名解析对话框

- [x] Task 6: 更新输入标签和提示信息
  - [x] SubTask 6.1: 更新目标输入框的提示信息
  - [x] SubTask 6.2: 添加IPv6示例说明

- [x] Task 7: 编译验证
  - [x] SubTask 7.1: 编译主程序项目，确保无编译错误

# Task Dependencies
- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 5] depends on [Task 4]
- [Task 6] depends on nothing
- [Task 7] depends on [Task 1, Task 2, Task 3, Task 4, Task 5, Task 6]
