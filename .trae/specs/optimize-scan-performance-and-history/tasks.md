# Tasks

- [x] Task 1: 调研现有扫描历史记录与导出机制
  - [x] SubTask 1.1: 查找 `ScanHistoryItem`、`ScanHistoryService` 等相关文件
  - [x] SubTask 1.2: 分析历史记录的存储格式（EF Core + SQLite）
  - [x] SubTask 1.3: 分析现有导出功能实现位置与格式（HistoryReportGenerator 生成 PDF/Word/HTML）
  - [x] SubTask 1.4: 确定专家模式结果映射到历史记录模型：新增 SaveScanResultAsync 重载，接收目标、端口结果、配置

- [x] Task 2: 优化 Rust 扫描服务性能与精度
  - [x] SubTask 2.1: 调整四种预设模式参数（更激进的本地参数、更稳的远程参数）
  - [x] SubTask 2.2: 实现自适应超时：根据前 N 个端口响应时间动态调整 timeout
  - [x] SubTask 2.3: 实现自适应并发：根据成功率动态调整并发数
  - [x] SubTask 2.4: 优化端口扫描顺序：优先扫描高频开放端口
  - [x] SubTask 2.5: 重新编译并部署 Rust 服务

- [x] Task 3: 优化 C# 内置扫描器性能与精度
  - [x] SubTask 3.1: 在 `PortScanner` 中应用自适应超时和并发
  - [x] SubTask 3.2: 实现快速模式优先扫描 Top 100 端口（PrioritizePorts 高频端口优先）
  - [x] SubTask 3.3: 实现重试确认逻辑，减少误报/漏报

- [x] Task 4: 实现扫描结果自动保存历史记录
  - [x] SubTask 4.1: 在 `ExpertModeWindow` 扫描完成后收集结果
  - [x] SubTask 4.2: 调用 `JsonDatabaseService` 保存历史记录
  - [x] SubTask 4.3: 确保历史记录包含扫描模式、参数、目标、结果数量
  - [x] SubTask 4.4: 在历史记录窗口中正确显示专家模式记录

- [x] Task 5: 实现扫描结果导出功能
  - [x] SubTask 5.1: 在专家模式 UI 添加"导出结果"按钮
  - [x] SubTask 5.2: 实现 CSV 导出（含 UTF-8 BOM）
  - [x] SubTask 5.3: 实现 JSON 导出
  - [x] SubTask 5.4: 在历史记录窗口中添加导出按钮

- [ ] Task 6: 集成验证
  - [ ] SubTask 6.1: 验证快速模式 100 端口扫描 < 3 秒
  - [ ] SubTask 6.2: 验证标准模式 1000 端口扫描 < 10 秒
  - [ ] SubTask 6.3: 验证扫描完成后历史记录自动增加一条
  - [ ] SubTask 6.4: 验证历史记录窗口能看到专家模式记录
  - [ ] SubTask 6.5: 验证 CSV/JSON 导出文件内容正确
  - [ ] SubTask 6.6: 验证 ExpertIntegrationTest 仍保持 23/23 100% 召回/精确率

# Task Dependencies
- Task 3 依赖于 Task 2
- Task 4 依赖于 Task 1
- Task 5 依赖于 Task 1 和 Task 4
- Task 6 依赖于 Task 2、Task 3、Task 4、Task 5