# 扫描历史记录PDF报告生成功能 Spec（基于44.docx格式）

## Why
当前扫描历史记录中的"生成报告"功能生成的PDF报告不符合专业标准，需要按照项目中的 **44.docx 专业报告模板** 的格式重新设计，使其达到可交付的企业级安全扫描报告质量。

## What Changes
- 新增 `HistoryReportGenerator.cs` 服务类，专门用于从历史记录数据生成符合44.docx格式的专业PDF报告
- 重构 `GenerateReportFromHistory_Click` 方法，集成新的历史记录报告生成器
- 实现与44.docx完全一致的7大章节结构（封面→目录→执行摘要→端口扫描→漏洞详情→风险评估→修复建议）
- 支持多选历史记录合并生成综合报告
- 添加报告预览功能（可选）

### 核心特性
1. **多节文档结构** - 封面/目录/正文各有独立页眉页脚
2. **5级风险颜色编码体系** - 严重(红)/高(橙)/中(黄)/低(绿)/信息(蓝)
3. **专业表格排版** - 深蓝表头(#2C3E50) + 斑马纹 + 自适应宽度
4. **统计卡片组件** - 带彩色数据的摘要展示
5. **完整中文支持** - 微软雅黑字体嵌入
6. **大数据量处理** - 分页+截断提示(>100条)

## Impact
- Affected specs: professional-pdf-report (复用其核心组件)
- Affected code: 
  - MainWindow.xaml.cs (GenerateReportFromHistory_Click方法)
  - Services/HistoryReportGenerator.cs (新建)
  - Models/CompleteScanResult.cs (可能需要扩展)

---

## ADDED Requirements

### Requirement: 历史记录PDF报告生成服务

系统 SHALL 提供 `HistoryReportGenerator` 静态类，专门用于从历史扫描记录数据生成符合44.docx格式的专业PDF报告。

#### 场景1：单条历史记录生成报告

**WHEN** 用户在扫描历史记录列表中选择一条记录并点击"生成报告"按钮，选择PDF格式
**THEN** 系统应：
1. 从 `CompleteScanResult` 对象提取端口扫描结果、漏洞检测结果、风险评估数据
2. 调用 `HistoryReportGenerator.GenerateFromHistoryRecord()` 方法
3. 生成包含以下章节的专业PDF：
   - 第1页：**封面页** - 深蓝装饰条 + 中英文标题 + 目标信息框(IP/时间/编号) + 安全评级徽章(彩色) + "机密-仅限内部使用"
   - 第2页：**目录页** - 自动列出5个主要章节及页码
   - 第3页：**执行摘要** - 4个统计卡片(风险等级/开放端口/漏洞总数/高危占比) + Top5高危漏洞表 + 服务分布统计
   - 第4-N页：**端口扫描结果表** - PdfPTable(端口号|协议|服务|版本|状态|响应时间)，深蓝表头+斑马纹+状态颜色编码
   - 第N+1-M页：**漏洞详情主表** - PdfPTable(序号|CVE|名称|等级|端口|服务|CVSS)，风险等级彩色背景+按等级分组+前10个详情块
   - 第M+1页：**风险评估展示** - 汇总表 + 进度条可视化 + 安全建议列表
   - 最后2-3页：**修复建议章节** - P1-P4优先级矩阵 + Top5修复建议卡 + 6类通用加固建议(网络/系统/应用/认证/数据/监控)
4. 除封面外每页显示统一页眉("网络安全漏洞扫描报告" | "NetSecurityScanner v1.0")和页脚("机密-内部文档" | "第X/Y页")
5. 使用微软雅黑字体确保中文正常显示
6. 保存到 `{应用目录}/Reports/HistorySecurityReport_{IP}_{时间戳}.pdf`
7. 显示成功提示并提供打开文件选项

#### 场景2：多条历史记录合并生成综合报告

**WHEN** 用户选择多条历史记录并点击"生成报告"，选择PDF格式
**THEN** 系统应：
1. 合并所有选中记录的数据：
   - 端口扫描结果取并集（去重）
   - 漏洞检测结果合并（去重，保留最高风险等级）
   - 风险评估数据加权平均
2. 在封面显示"综合扫描报告"标题
3. 在执行摘要中添加"本次报告基于 N 次历史扫描记录合并生成"说明
4. 其他章节结构与单条记录相同

#### 场景3：空数据处理

**WHEN** 选中的历史记录无端口扫描结果或漏洞检测结果
**THEN** 系统应：
- 显示友好提示："选中的历史记录中无有效扫描数据，无法生成报告"
- 不生成空PDF文件
- 不抛出异常

#### 场景4：字体加载失败降级

**WHEN** 系统无法加载任何中文字体（msyh.ttc/simhei/simsun均不可用）
**THEN** 系统应：
- 回退到Helvetica字体（中文可能显示为方块）
- 在日志中记录警告但不中断报告生成
- 继续生成完整结构的PDF（仅字体不同）

---

## MODIFIED Requirements

### Requirement: GenerateReportFromHistory_Click 入口方法优化

现有方法 SHALL 进行修改以支持新的历史记录报告生成器：

**修改前行为**：
```csharp
filePath = GenerateProfessionalPdfReport(allPortResults, allVulnerabilityResults, allRiskAssessmentItems, targetIp);
```

**修改后行为**：
```csharp
// 使用专门的 HistoryReportGenerator 生成符合44.docx格式的报告
if (selectedHistoryRecords.Count == 1)
{
    filePath = HistoryReportGenerator.GenerateFromHistoryRecord(selectedHistoryRecords[0]);
}
else if (selectedHistoryRecords.Count > 1)
{
    filePath = HistoryReportGenerator.GenerateFromMultipleRecords(selectedHistoryRecords.ToList());
}
```

**关键改进**：
1. 区分单条/多条记录的不同处理逻辑
2. 传递完整的 CompleteScanResult 对象（而非拆分后的子集合）
3. 支持传递额外的元数据（如报告标题自定义、公司Logo路径等）

---

## 技术实现规范

### 1. 文件结构与依赖关系

```
Services/
├── ProfessionalPdfReportGenerator.cs    # 已有 - 主窗口导出报告使用（保留不变）
└── HistoryReportGenerator.cs             # 新建 - 历史记录专用报告生成器
    ├── 依赖 ProfessionalPdfReportGenerator 的基础组件：
    │   ├── FontCollection (字体管理)
    │   ├── GetRiskLevelColor() (颜色编码)
    │   └── AddErrorPlaceholder() (错误占位符)
    └── 新增/重写的方法：
        ├── GenerateFromHistoryRecord() - 单条记录入口
        ├── GenerateFromMultipleRecords() - 多条记录入口
        ├── GenerateCoverPage() - 封面页（支持多记录模式）
        ├── GenerateTableOfContents() - 目录页
        ├── GenerateExecutiveSummary() - 执行摘要
        ├── GeneratePortScanSection() - 端口扫描表格
        ├── GenerateVulnerabilitySection() - 漏洞详情表格+详情块
        ├── GenerateRiskAssessmentSection() - 风险评估展示
        ├── GenerateRemediationSection() - 修复建议章节
        └── SetupHeaderFooter() - 页眉页脚设置
```

### 2. 与44.docx格式的一致性要求

| 44.docx元素 | PDF实现方式 | iTextSharp API |
|------------|-------------|----------------|
| 封面深蓝装饰条 | Rectangle填充 | `cb.SetColorFill(0.16, 0.24, 0.31)` |
| 主标题24pt粗体 | Paragraph+Font | `new Font(baseFont, 24, Font.BOLD)` |
| 目标信息框(无边框) | PdfPTable(无边框) | `table.DefaultCell.Border = Rectangle.NO_BORDER` |
| 安全评级徽章(彩色) | PdfPCell背景色 | `cell.BackgroundColor = new BaseColor(0xF4, 0x43, 0x36)` |
| 目录点状引导线 | TabStop + Leader | `tab.SetLeader(new DottedLineLeader())` |
| 表头深蓝#2C3E50白字 | PdfPCell样式 | `cell.BackgroundColor = new BaseColor(0x2C, 0x3E, 0x50)` |
| 斑马纹偶数行#F8F9FA | 行背景色交替 | `row.BackgroundColor = (i%2==0) ? white : lightGray` |
| 风险等级彩色单元格 | 5色背景+边框 | `GetRiskLevelBackgroundColor(level)` |
| 页眉灰色分隔线 | Line绘制 | `cb.MoveTo(x1, y); cb.LineTo(x2, y); cb.Stroke()` |
| 进度条(████░░) | Unicode字符或小矩形 | `new String('█', percentage/10) + new String('░', 10-percentage/10)` |

### 3. 字体规范（严格遵循44.docx）

```csharp
// 字体回退链（必须按此顺序尝试）
string[] fontPaths = {
    @"C:\Windows\Fonts\msyh.ttc",      // 1. 微软雅黑（首选）
    @"C:\Windows\Fonts\simhei.ttf",     // 2. 黑体
    @"C:\Windows\Fonts\simsun.ttc",     // 3. 宋体
    null                                 // 4. Helvetica（最终回退）
};

// 字号规范
const float FONT_TITLE_MAIN = 24f;      // 主标题
const float FONT_TITLE_SECTION = 18f;   // 一级章节标题
const float FONT_TITLE_SUBSECTION = 14f; // 二级章节标题
const float FONT_BODY = 10f;            // 正文
const float FONT_TABLE_HEADER = 9f;     // 表格表头
const float FONT_TABLE_CELL = 9f;       // 表格单元格
const float FONT_FOOTER = 8f;           // 页眉页脚
const float FONT_STAT_NUMBER = 16f;     // 统计数字（加粗）
const float FONT_CONFIDENTIAL = 9f;     // 机密标识（红色加粗）
```

### 4. 配色方案（严格遵循44.docx）

```csharp
// 主题色板
public static readonly Color COLOR_PRIMARY = Color.FromArgb(0x2C, 0x3E, 0x50);      // 深岩蓝（表头/标题）
public static readonly Color COLOR_ACCENT = Color.FromArgb(0x34, 0x9D, 0xDB);       // 亮蓝色（强调/链接）
public static readonly Color COLOR_TEXT_PRIMARY = Color.Black;                       // 正文字色
public static readonly Color COLOR_TEXT_SECONDARY = Color.FromArgb(0x33, 0x33, 0x33); // 深灰文字
public static readonly Color COLOR_ZEBRA_EVEN = Color.FromArgb(0xF8, 0xF9, 0xFA);     // 斑马纹偶数行
public static readonly Color COLOR_BORDER_LIGHT = Color.FromArgb(0xDC, 0xDC, 0xDC);   // 浅灰边框
public static readonly Color COLOR_SEPARATOR = Color.FromArgb(0xC8, 0xC8, 0xC8);      // 分隔线
public static readonly Color COLOR_CONFIDENTIAL = Color.FromArgb(0xC0, 0x39, 0x2B);   // 机密红

// 风险等级5色编码
public static Dictionary<string, RiskColorScheme> RiskColors = new() {
    ["严重"] = new { Text=Color.FromArgb(0xF4,0x43,0x36), Bg=Color.FromArgb(0xFF,0xEB,0xEE), Border=Color.FromArgb(0xF4,0x43,0x36) },
    ["高"]   = new { Text=Color.FromArgb(0xFF,0x98,0x00), Bg=Color.FromArgb(0xFF,0xF3,0xE0), Border=Color.FromArgb(0xFF,0x98,0x00) },
    ["中"]   = new { Text=Color.FromArgb(0xFF,0xC1,0x07), Bg=Color.FromArgb(0xFF,0xFF,0xE0), Border=Color.FromArgb(0xFF,0xC1,0x07) },
    ["低"]   = new { Text=Color.FromArgb(0x4A,0xF5,0x39), Bg=Color.FromArgb(0xE8,0xF5,0xE9), Border=Color.FromArgb(0x4A,0xF5,0x39) },
    ["信息"] = new { Text=Color.FromArgb(0x21,0x9F,0xF3), Bg=Color.FromArgb(0xE3,0xF2,0xFD), Border=Color.FromArgb(0x21,0x9F,0xF3) }
};
```

### 5. 页面布局参数

```csharp
// A4纸张
Document.PageSize = PageSize.A4;  // 210 x 297 mm

// 页边距（与44.docx一致）
float MARGIN_LEFT = 60f;    // ~21mm
float MARGIN_RIGHT = 60f;
float MARGIN_TOP = 72f;     // ~25mm（为页眉留空间）
float MARGIN_BOTTOM = 60f;

// 页眉位置
float HEADER_Y = document.Top - 20f;
float HEADER_HEIGHT = 28f;

// 页脚位置  
float FOOTER_Y = 28f;

// 封面装饰条高度
float COVER_BAR_HEIGHT = 80f;
```

---

## 验收标准

### 功能验收
- [ ] 从单条历史记录可生成完整7章PDF报告
- [ ] 从多条历史记录可生成合并综合报告
- [ ] PDF可用Adobe Reader/Foxit Reader正常打开
- [ ] 中文内容清晰可读无乱码
- [ ] 所有章节页眉页脚正确显示（除封面）
- [ ] 风险等级颜色编码正确（5种颜色）
- [ ] 表格有斑马纹和深蓝表头
- [ ] 空数据显示友好提示而非崩溃

### 格式验收（对比44.docx）
- [ ] 封面有深蓝装饰条和中英文双标题
- [ ] 封面有目标信息框和安全评级徽章
- [ ] 目录自动列出章节及正确页码
- [ ] 执行摘要有4个统计卡片
- [ ] 端口扫描表6列完整且状态着色
- [ ] 漏洞详情表按风险等级分组排列
- [ ] 前10个漏洞有详细信息块
- [ ] 风险评估有进度条可视化
- [ ] 修复建议有P1-P4优先级矩阵和6类通用建议
- [ ] 底部有"机密-仅限内部使用"标注

### 性能验收
- [ ] 100条以内漏洞报告生成时间 < 5秒
- [ ] 500条漏洞报告生成时间 < 15秒
- [ ] 内存占用峰值 < 200MB
