# Tasks

- [x] Task 1: LicenseDialog 增加机器码一键复制功能
  - [x] SubTask 1.1: 修改 LicenseDialog.xaml — 机器码行改为StackPanel(Orientation=Horizontal)，包含TextBlock和Button
  - [x] SubTask 1.2: 修改 LicenseDialog.xaml.cs — 添加 CopyMachineIdButton_Click 方法，复制到剪贴板，按钮文字短暂变为"已复制"

- [x] Task 2: 创建发放记录模型和服务
  - [x] SubTask 2.1: 创建 LicenseRecord.cs — 发放记录模型（RecordId, LicenseCode, LicenseType, MachineId, IssuedTime, ExpiryTime, Notes）
  - [x] SubTask 2.2: 创建 LicenseRecordService.cs — 发放记录JSON数据库服务（添加/查询/删除/保存/加载）

- [x] Task 3: 重构生成器界面为TabControl多标签页
  - [x] SubTask 3.1: 修改 MainWindow.xaml — TabControl三标签页（生成授权码、批量发放、发放记录）
  - [x] SubTask 3.2: Tab2批量发放界面 — 授权类型选择、机器码多行输入、导入文件按钮、批量生成/导出按钮
  - [x] SubTask 3.3: Tab3发放记录界面 — 搜索框、DataGrid记录列表、刷新/删除按钮

- [x] Task 4: 实现批量发放逻辑
  - [x] SubTask 4.1: BatchGenerateButton_Click — 解析多行机器码，循环生成，调用LicenseRecordService记录
  - [x] SubTask 4.2: ImportFileButton_Click — 打开文件对话框读取txt文件
  - [x] SubTask 4.3: BatchExportButton_Click — 导出批量生成的授权码

- [x] Task 5: 实现发放记录查询逻辑
  - [x] SubTask 5.1: RefreshRecords — 加载所有记录到DataGrid
  - [x] SubTask 5.2: SearchRecords — 按机器码过滤记录
  - [x] SubTask 5.3: DeleteRecordButton_Click — 删除选中记录

- [x] Task 6: 修改生成逻辑自动记录发放
  - [x] SubTask 6.1: GenerateButton_Click — 生成后调用LicenseRecordService添加记录
  - [x] SubTask 6.2: CalculateExpiryTime — 根据授权类型计算到期时间

- [x] Task 7: 编译验证
  - [x] SubTask 7.1: 主程序编译成功，0个错误
  - [x] SubTask 7.2: 生成器编译成功，0个错误

# Task Dependencies
- [Task 2] depends on nothing
- [Task 1] depends on nothing
- [Task 3] depends on [Task 2]
- [Task 4] depends on [Task 2, Task 3]
- [Task 5] depends on [Task 2, Task 3]
- [Task 6] depends on [Task 2]
- [Task 7] depends on [Task 1, Task 4, Task 5, Task 6]
