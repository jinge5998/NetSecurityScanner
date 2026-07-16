# 扫描历史记录功能全栈重写设计文档

## 概述

重新设计扫描历史记录功能，修复 CheckBox 勾选 bug，统一数据模型、服务层和 UI 层，支持 PDF/Word/HTML/Excel 四种报告格式。

## 架构设计

```
┌─────────────────────────────────────────────┐
│                  UI 层                        │
│  ScanHistoryWindow.xaml (WPF DataGrid)       │
│  - CheckBox 勾选（DataGridTemplateColumn）    │
│  - 搜索/筛选/排序                             │
│  - 批量操作工具栏                              │
├─────────────────────────────────────────────┤
│               服务层                          │
│  ScanHistoryService (CRUD)                   │
│  HistoryReportGenerator (PDF/Word/HTML/Excel) │
├─────────────────────────────────────────────┤
│               数据层                          │
│  ScanDbContext (EF Core + SQLite)            │
│  ScanHistory / VulnerabilityRecord 模型       │
└─────────────────────────────────────────────┘
```

## 1. 数据模型（保留现有，微调）

### ScanHistory 模型
保留现有字段，新增：
- `ReportFormats` (string) — 已生成的报告格式列表（逗号分隔，如 "PDF,Word"）

### SelectableScanHistory 包装类
- 保留 INotifyPropertyChanged 实现
- **移除所有 IValueConverter**（BoolToCheckConverter 等），简化绑定

## 2. 数据库层（保留 SQLite + EF Core）

### ScanDbContext
- 保留现有实现
- 数据库路径：`Data/ScanHistory.db`

### ScanHistoryService
- 保留现有 CRUD 方法
- 新增 `DeleteMultipleAsync(List<string> scanIds)` 批量删除
- 新增 `GetScanHistoryByIdsAsync(List<string> scanIds)` 按ID列表查询

## 3. UI 层 — ScanHistoryWindow 重写

### 关键修复：CheckBox 勾选

**根因**：`Item_PropertyChanged` 中调用 `HistoryDataGrid.Items.Refresh()` 导致 CheckBox 被重建，状态丢失。

**方案**：
1. 使用 `DataGridTemplateColumn` + CheckBox + `Checked`/`Unchecked` 事件
2. **禁止在任何 IsSelected 变化回调中调用 `Items.Refresh()`**
3. 全选/反选/取消选择按钮：修改 IsSelected 后调用 `Items.Refresh()`（这些是批量操作，需要刷新）
4. 行高亮通过 `DataTrigger Binding="{Binding IsSelected}"` 自动实现

### UI 布局

```
┌──────────────────────────────────────────────────┐
│  搜索框  │  风险等级筛选  │  时间筛选  │  刷新按钮  │
├──────────────────────────────────────────────────┤
│  全选 │ 反选 │ 取消选择 │  已选:0/总:0  │ 生成报告 │ 删除选中 │
├──────────────────────────────────────────────────┤
│  ☐ │ # │ 扫描ID │ 目标 │ 时间 │ 模式 │ 漏洞数 │ ... │
│  ☐ │ 1 │ xxx    │ 192..│ ...  │ 快速 │   5    │ ... │
│  ☐ │ 2 │ yyy    │ 10.. │ ...  │ 全量 │   3    │ ... │
├──────────────────────────────────────────────────┤
│  统计: 总扫描 20 │ 本月 5 │ 严重 3 │ 高危 8 │ ...   │
└──────────────────────────────────────────────────┘
```

### 报告生成流程

1. 用户勾选记录 → 点击"生成报告"
2. 弹出 ReportFormatDialog 选择格式（PDF/Word/HTML/Excel）
3. 选择保存路径
4. 调用 HistoryReportGenerator 生成报告
5. 显示进度窗口
6. 完成后更新数据库中的报告路径

## 4. 报告生成器

### HistoryReportGenerator（保留现有 PDF 生成）
- PDF：iTextSharp（已有实现）
- Word：HistoryWordReportGenerator（已有实现）
- HTML：HtmlReportGenerator（已有实现）
- Excel：新增 EPPlus/ClosedXML 实现

### 批量报告
- 支持多条记录合并为一份报告
- 支持每条记录单独生成报告

## 5. 修改文件清单

| 文件 | 操作 | 说明 |
|---|---|---|
| `ScanHistoryWindow.xaml` | 重写 | DataGrid + CheckBox + 工具栏 |
| `ScanHistoryWindow.xaml.cs` | 重写 | 事件处理、数据绑定、报告生成 |
| `ScanHistoryItem.cs` | 修改 | 简化，移除不需要的 Converter |
| `ScanHistoryService.cs` | 修改 | 新增批量操作方法 |
| `ScanHistory.cs` | 微调 | 新增 ReportFormats 字段 |
| `HistoryReportGenerator.cs` | 修改 | 新增 Excel 格式支持 |
| `ReportFormatDialog.xaml` | 修改 | 支持 4 种格式选择 |

## 6. CheckBox 勾选修复规则（核心）

1. **永远不在 `Item_PropertyChanged` 中调用 `Items.Refresh()`**
2. **永远不在 `CheckBox_Checked`/`CheckBox_Unchecked` 中调用 `Items.Refresh()`**
3. **只在批量操作（全选/反选/取消选择）后调用 `Items.Refresh()`**
4. **使用 `Checked`/`Unchecked` 事件，不用 `Click` 事件**
5. **不设 `DataGrid.IsReadOnly`，不设 `CheckBox.Focusable=False`**
