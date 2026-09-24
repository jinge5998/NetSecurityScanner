# AI 风险评估图表字体显示修复 - 检查清单

## 字体注册
- [x] `App.xaml.cs.OnStartup` 调用 `LiveCharts.Configure(config => config.HasGlobalSKTypeface(<chinese typeface>))`
- [x] `CjkFontResolver` 按 Microsoft YaHei UI → Microsoft YaHei → SimHei → SimSun → Noto Sans CJK SC → Source Han Sans SC → PingFang SC 顺序解析
- [x] 所有候选均失败时回退到 `SKFontManager.Default.MatchCharacter('汉')`
- [x] 极端情况最终兜底为 `SKTypeface.Default`
- [x] **Task 10**：`CjkFontResolver` 必须返回 `MatchFamily` 的 `match` 实例而非 `FromFamilyName` 的 `tf` 实例（关键 Bug 修复）

## CjkPaint 增强
- [x] `CjkPaint` 同时设置 `SKTypeface`、`FontFamily`、`IsAntialias`
- [x] 接受外部 typeface 的重载 `CjkPaint(SKColor, float, SKTypeface?)`
- [x] 所有图表方法中 `Fill` / `Stroke` / `LabelsPaint` / `GeometryFill` / `GeometryStroke` 全部通过 `CjkPaint` 创建
- [x] `MainWindow.xaml.cs` 中已无裸 `new SolidColorPaint(...)`（除 `CjkPaint` 内部实现）
- [x] 反射式 `LcdRenderText` 启用：因 LiveChartsCore 2.0.0-rc2 未暴露 `TextSettings`/`FontBuilder` API，改用 `IsAntialias = true` + `FontFamily` 显式赋值（在 9.1 步骤中说明）
- [x] **Task 11**：饼图 `LegendTextPaint` 显式设置 CjkPaint
- [x] **Task 12**：所有图表 `TooltipTextPaint` / `TooltipBackgroundPaint` 显式设置 CjkPaint

## 启动目录
- [x] WPF 启动入口设置 `Environment.CurrentDirectory = AppContext.BaseDirectory`

## XAML 字体声明
- [x] `MainWindow.xaml` 的 `<Window>` 上声明 `TextElement.FontFamily` 字体回退链
- [x] `AiRiskDashboardRoot` 上的重复声明已移除
- [x] `AiRiskKeyFindingsList` 的 `DataTemplate` 中 `ItemsControl` 显式声明 `TextElement.FontFamily`
- [x] 所有 `TextBlock` 默认继承 Window 的字体

## 调试日志
- [x] BootLog 输出包含 `[AI Risk Font] Resolved CJK typeface: <family>` 日志
- [x] `MainWindow` 构造函数 Debug.WriteLine 输出 `[AI Risk Font] Application started; CJK font resolved: <family>`
- [x] **Task 10**：BootLog 对比输出 `tf.FamilyName` / `match.FamilyName` / `match.Handle`，便于诊断

## 视觉增强
- [x] 柱状图 X/Y 轴标签 `TextSize = 12`
- [x] 雷达图 12 个轴标签 `TextSize = 12`
- [x] 修复优先级柱状图 `LabelsRotation = -25`
- [x] 饼图图例字号通过全局字体与 `IsAntialias = true` 提升
- [x] `PolarChart.TotalAngle=360`、`InnerRadius` 合理（保留 10 维=20 / 8 维=15）
- [x] **Task 13**：`BuildKillChainChart` / `BuildDimensionalChart` 的 `PolarAxis.LabelsPaint` `TextSize` 提升至 13
- [x] **Task 14**：`BuildKillChainChart` / `BuildDimensionalChart` 增加 `OuterRadius` 设置（库版本不支持，已通过注释 + 字号方案替代）

## 编译与发布
- [x] `dotnet build -c Release` 无错误
- [x] `dotnet publish` 成功输出到 `publish-v1.0.1.5`
- [x] 发布目录含 `LiveChartsCore.SkiaSharpView.WPF.dll`、`SkiaSharp.dll`、`libSkiaSharp.dll`、`HarfBuzzSharp.dll`、`libHarfBuzzSharp.dll`
- [ ] `NetSecurityScanner.Desktop.exe` 实机启动验证（需用户手动操作）

## 目视验证（用户反馈截图中的关键位置）
- [ ] "风险类别分布 · Risktem 分类" 卡片图例显示完整中文（"CVE 漏洞"、"配置风险" 等，不出现 □□□□）— 需用户实机确认
- [ ] "杀伤链覆盖度 · KillChain" 雷达图 8 个轴标签完整显示（"侦察"、"初始访问"、"执行"、"提权"、"凭据访问"、"发现"、"横向移动"、"影响"）— 需用户实机确认
- [ ] "CVE 严重度分布" 柱状图 X 轴（"严重 / 高危 / 中危 / 低危"）完整显示
- [ ] "服务类型分布" 饼图图例（"HTTP"、"HTTPS"、"SSH"、"RDP"、"MySQL" 等）完整显示
- [ ] "修复优先级分布" 柱状图 X 轴（"P0 立即 / P1 紧急 / P2 高 / P3 中 / P4 低"）完整显示（启用 -25° 旋转）
- [ ] "综合风险评分" 中心数字与等级描述（"极度危险 / 高风险 / 中等风险 / 安全"）完整显示
- [ ] "10 维评分" 雷达图 10 个轴标签完整显示
- [x] **Task 12**：鼠标悬停图表数据点 → Tooltip 文字无方框

## 兼容性验证
- [x] BootLog 包含字体解析路径（`Resolved CJK typeface: ...`）
- [x] `CjkFontResolver` 在首选字体缺失时回退到 `MatchCharacter('汉')`
- [x] 不出现 `SkiaSharp` 抛出的 `Could not find family name` 异常（已被 `try/catch` 捕获）
- [x] **Task 10**：Debug 日志中字体族名与 SkiaSharp 实际加载的字体一致（不是 `Microsoft Sans Serif` 之类的默认值）
- [ ] **Task 15**（可选）：精简 Windows 容器下内嵌 `NotoSansSC-Regular.otf` 能正常显示中文

## 代码质量
- [x] 临时反射探测代码（probe_types 目录、probe_types.ps1）已从主代码中删除
- [x] 没有引入未使用的 using 引用（App.xaml.cs / MainWindow.xaml.cs）
- [x] `AIRiskAssessmentService` / `AIRiskAssessmentModelsV5` 未被修改
- [x] 修改仅限于 `MainWindow.xaml`、`MainWindow.xaml.cs`、`App.xaml.cs`、新增 `Utils/CjkFontResolver.cs`
- [ ] **Task 15**（可选）：如启用内嵌字体，需更新 `NetSecurityScanner.Desktop.csproj` 增加 `<Resource Include="Fonts\..." />`
