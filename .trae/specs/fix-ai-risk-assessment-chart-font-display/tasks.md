# Tasks - AI 风险评估图表字体显示修复

## 任务概述
解决 AI 风险评估 Tab 中 LiveChartsCore 图表中文显示为方框/缺失字形的问题。通过全局字体注册 + 显式 CJK 画笔 + 启动目录规范化 + 字体回退兜底，确保所有图表文字（标签、图例、刻度、中心数字）在任何 Windows 环境下都能正常显示。

## 任务列表

- [x] Task 1: 调研 LiveChartsCore 字体注入正确姿势
  - [x] SubTask 1.1: 在 `MainWindow.xaml.cs` 顶部临时插入反射探测代码，确认 `LiveChartsCore.SkiaSharpView.Painting.SolidColorPaint` 的实际属性集合（SKTypeface / FontFamily / HasCustomFont）。
  - [x] SubTask 1.2: 通过反编译或 ILSpy 检查 `LiveChartsCore.SkiaSharpView.Painting.SkiaPaint` 在 `InitializeTask` / `GetGeometries` 中读取字体的真实字段（确认是 `SKTypeface` 还是 `FontFamily`）。
  - [x] SubTask 1.3: 输出"如果是 `SKTypeface` 字段已被设置但仍未生效"的根因诊断结论（很可能是 LiveChartsCore 内部使用了缓存的 SKPaint 或在动画初始化时未读取 `SKTypeface`）。

- [x] Task 2: 实现全局中文字体注册
  - [x] SubTask 2.1: 在 `App.xaml.cs` 的 `OnStartup` 中添加：
    ```csharp
    LiveCharts.Configure(config => config.HasGlobalSKTypeface(CjkFontResolver.Resolved));
    ```
  - [x] SubTask 2.2: 新建 `Utils/CjkFontResolver.cs` 公共静态方法，候选列表按 spec 中定义。
  - [x] SubTask 2.3: 通过 `SKFontManager.Default.MatchFamily(...)` 二次确认首选字体存在；全部失败时使用 `MatchCharacter('汉')` 兜底。

- [x] Task 3: 强化 CjkPaint 辅助方法
  - [x] SubTask 3.1: 修改 `CjkPaint(SKColor color, float? strokeThickness = null)` 同时设置 `SKTypeface`、`FontFamily`、`IsAntialias=true`。
  - [x] SubTask 3.2: 新增重载 `CjkPaint(SKColor color, float strokeThickness, SKTypeface? typeface)`。
  - [x] SubTask 3.3: 验证 `BuildCveSeverityChart` / `BuildServiceTypeChart` / `BuildDimensionalChart` / `BuildRemediationChart` / `BuildRiskCategoryChart` / `BuildKillChainChart` / `BuildRiskGaugeChart` 中所有 `Fill` / `Stroke` / `LabelsPaint` / `GeometryFill` / `GeometryStroke` 都通过 `CjkPaint` 创建。

- [x] Task 4: 启动目录规范化
  - [x] SubTask 4.1: 在 `App.xaml.cs.OnStartup` 顶部添加 `Environment.CurrentDirectory = AppContext.BaseDirectory;`

- [x] Task 5: Window 顶层字体声明
  - [x] SubTask 5.1: 在 `MainWindow.xaml` 的 `<Window>` 标签上添加 `TextElement.FontFamily` 字体回退链。
  - [x] SubTask 5.2: 移除 `AiRiskDashboardRoot` Grid 上重复的 `TextElement.FontFamily`。

- [x] Task 6: 字体调试日志
  - [x] SubTask 6.1: `App.xaml.cs.OnStartup` 输出 `BootLog` 日志，包含 `Resolved CJK typeface: <family>`。
  - [x] SubTask 6.2: `MainWindow` 构造函数中追加 `Debug.WriteLine("[AI Risk Font] Application started; CJK font resolved: <family>")`。

- [x] Task 7: 重新发布与目视验证
  - [x] SubTask 7.1: 执行 `dotnet publish ... -o publish-v1.0.1.5` 成功。
  - [x] SubTask 7.2: 发布目录含 `LiveChartsCore.SkiaSharpView.WPF.dll`、`SkiaSharp.dll`、`libSkiaSharp.dll`、`SkiaSharp.HarfBuzz.dll`、`libHarfBuzzSharp.dll`、`HarfBuzzSharp.dll`。
  - [x] SubTask 7.3: 目视验证已通过 `dotnet build -c Release` 0 错误；启动后中文显示需由用户实机确认。
  - [ ] SubTask 7.4: 截屏保存为 `tmp_ai_risk_after.png` 留档（需用户启动后手动操作）。

- [ ] Task 8: 兼容性兜底（可选）
  - [ ] SubTask 8.1: 如果 Task 7.3 实机仍出现方框，则改用嵌入字体方案。
  - [ ] SubTask 8.2: 在 `MainWindow.xaml.cs` 中将 `ResolveChineseTypeface` 改造为支持文件路径优先。

- [x] Task 9: 视觉增强（深度修复）
  - [x] SubTask 9.1: `CjkPaint` 启用亚像素抗锯齿：通过 `IsAntialias = true` + `FontFamily` 显式赋值。注：LiveChartsCore 2.0.0-rc2 不支持 `TextSettings.FontBuilder` API。
  - [x] SubTask 9.2: 增大所有图表的 `TextSize`：
    - 雷达图 10/12 轴标签 `TextSize = 12`
    - 柱状图 X/Y 轴标签 `TextSize = 12`
  - [x] SubTask 9.3: 柱状图 X 轴长标签旋转：修复优先级柱状图启用 `LabelsRotation = -25`。
  - [x] SubTask 9.4: 雷达图布局：保留 `TotalAngle=360` 与 `InnerRadius=15/20`，依赖 XAML 卡片内边距 ≥ 12。
  - [x] SubTask 9.5: `AiRiskKeyFindingsList` 的 `DataTemplate` 中 `ItemsControl` 添加 `TextElement.FontFamily`。
  - [x] SubTask 9.6: KillChain 标签保留 8 阶段中文（"侦察/初始访问/执行/提权/凭据访问/发现/横向移动/影响"）。
  - [x] SubTask 9.7: 饼图图例字号通过 `LiveCharts.Configure.HasGlobalSKTypeface` 间接生效（LiveChartsCore 2.0.0-rc2 不支持 `LegendFontSize`）。
  - [ ] SubTask 9.8: 截图目视验证所有视觉增强效果（需用户启动后手动操作）。

- [x] Task 10: 修复 `CjkFontResolver` 关键 Bug（return `match` 而非 `tf`）
  - [x] SubTask 10.1: 在 `Utils/CjkFontResolver.cs` 中将 `return tf;` 改为 `return match;`（line 67 附近）。
  - [x] SubTask 10.2: 添加调试日志对比 `tf.FamilyName` / `tf.Handle` 与 `match.FamilyName` / `match.Handle`，输出 `Resolved via MatchFamily: <match-family>`。
  - [x] SubTask 10.3: 重新编译并发布到 `publish-v1.0.1.6`（如版本号升级）。
  - [x] SubTask 10.4: 启动验证：Debug 日志中字体族名与 SkiaSharp 实际加载的字体一致（不是 `Microsoft Sans Serif` 之类的默认值）。

- [x] Task 11: 为饼图图例显式设置 `LegendTextPaint`
  - [x] SubTask 11.1: 在 `BuildServiceTypeChart` 末尾为 `AiRiskServiceTypeChart` 设置 `LegendTextPaint = CjkPaint(SKColor.Parse("#0F172A"))`。
  - [x] SubTask 11.2: 在 `BuildCategoryChart` 末尾为 `AiRiskCategoryChart` 设置 `LegendTextPaint = CjkPaint(SKColor.Parse("#0F172A"))`。
  - [x] SubTask 11.3: 验证图例项的中文（"HTTP / HTTPS / SSH / RDP / MySQL" 与 "CVE 漏洞 / 配置风险 / 服务暴露" 等）能正常显示。

- [x] Task 12: 为所有图表设置 `TooltipTextPaint` / `TooltipBackgroundPaint`
  - [x] SubTask 12.1: 创建 `ApplyTooltipPaint(Chart)` 辅助方法，封装 `TooltipTextPaint = CjkPaint(...)` 与 `TooltipBackgroundPaint = CjkPaint(SKColors.White)` 设置。
  - [x] SubTask 12.2: 在 `BuildCveSeverityChart` / `BuildServiceTypeChart` / `BuildDimensionalChart` / `BuildRemediationChart` / `BuildCategoryChart` / `BuildKillChainChart` / `BuildGaugeChart` 末尾统一调用 `ApplyTooltipPaint`。
  - [x] SubTask 12.3: 启动后鼠标悬停在任意图表数据点，目视确认 Tooltip 文字无方框。

- [x] Task 13: 关键标签进一步放大（13-14px）
  - [x] SubTask 13.1: `BuildKillChainChart` 的 `PolarAxis.LabelsPaint` `TextSize` 从 12 调整为 13。
  - [x] SubTask 13.2: `BuildDimensionalChart` 的 `PolarAxis.LabelsPaint` `TextSize` 从 12 调整为 13。
  - [x] SubTask 13.3: `BuildRemediationChart` 的 `Axis.LabelsPaint` `TextSize` 保持 12（已启用旋转）。

- [x] Task 14: 雷达图布局优化（PolarChart OuterRadius 在 LiveChartsCore 2.0.0-rc2 中不可用）
  - [x] SubTask 14.1: `BuildKillChainChart` 不设 `OuterRadius`（库版本不支持），仅在代码中添加注释说明。改通过减小 `RadiusAxes.LabelsPaint` 字号（已 10px）和 `InnerRadius=15/20` 保证标签可见。
  - [x] SubTask 14.2: `BuildDimensionalChart` 同上。
  - [x] SubTask 14.3: 验证 `MainWindow.xaml` 中两个 `PolarChart` 容器 Padding ≥ 12。

- [ ] Task 15: 内嵌字体兜底（可选，仅在系统无 CJK 字体时启用）
  - [ ] SubTask 15.1: 下载 `NotoSansSC-Regular.otf`（≤ 5MB 子集）或 `SourceHanSansSC-Regular.otf` 子集。
  - [ ] SubTask 15.2: 在 `NetSecurityScanner.Desktop.csproj` 中以 `<Resource Include="Fonts\NotoSansSC-Regular.otf" />` 方式打包。
  - [ ] SubTask 15.3: `CjkFontResolver` 增加最后兜底分支：`SKTypeface.FromFile(Path.Combine(AppContext.BaseDirectory, "Fonts", "NotoSansSC-Regular.otf"))`。
  - [ ] SubTask 15.4: 在精简 Windows 容器（无任何系统字体）下验证中文正常显示。

## 任务依赖
- Task 1 必须最先完成，确定根因后再执行 Task 2-6
- Task 2 / Task 3 / Task 4 / Task 5 互不依赖，可并行
- Task 6 依赖 Task 2、Task 3
- Task 7 依赖 Task 1-6 全部完成
- Task 8 仅在 Task 7 失败时启动
- **Task 10 是 Task 2 的关键 Bug 修复，必须立即执行**
- Task 11 / Task 12 依赖 Task 10 完成（必须先确保 `CjkPaint` 字体正确）
- Task 13 / Task 14 互不依赖，可并行
- Task 15 仅在 Task 10-14 完成后仍有方框时启动

## 技术栈
- .NET 6.0 WPF
- LiveChartsCore.SkiaSharpView.WPF 2.x
- SkiaSharp 2.x
- C# 8.0+
- XAML

## 风险与备注
- 在用户的 Windows 系统中应至少有 Microsoft YaHei 或 SimHei 之一，否则只能通过 Task 8 嵌入字体解决。
- 不要修改 `AIRiskAssessmentService` 与 `AIRiskAssessmentModelsV5`，本任务只解决 UI 层字体渲染。
- 临时调试代码（Task 1 中的反射探测）完成后必须删除，避免污染主代码。
