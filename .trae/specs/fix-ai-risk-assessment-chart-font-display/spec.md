# AI 风险评估图表字体显示修复规格

## Why
AI 风险评估 Tab 中的 LiveChartsCore 图表（饼图、雷达图、柱状图、极坐标图）中的中文字符出现多种显示问题：
1. **方框/缺失字形**：部分字符（如雷达图长标签 "权限提升"）在某些字体回退路径下完全无法渲染。
2. **文字截断**：图例项、轴标签超出容器边界被裁切。
3. **字号过小**：标签 10-11px 在 1920×1080 屏幕上几乎看不清。
4. **抗锯齿差**：在白底背景下不带 LCD 渲染的字体边缘发虚。
5. **Tooltip / 中心数字 / 标题副标题** 等非图表轴标签元素也使用 SkiaSharp 渲染，需同样处理。

WPF 顶层 `TextElement.FontFamily` 只对原生 WPF 控件（TextBlock、Button 等）生效，LiveChartsCore 通过 SkiaSharp 直接绘制到画布，必须显式注入支持中文的 `SKTypeface` 并确保 `SolidColorPaint` 内部的 SKPaint 使用该字体。当前的 `CjkPaint` 辅助方法仅设置了 `SKTypeface` 属性，但 LiveChartsCore 2.x 在某些路径下并不会回读该字段，导致中文仍以默认字体（不含中文字形）渲染，最终呈现为方框。

## What Changes
- **全局注入中文字体**：通过 `LiveCharts.Configure(...).HasGlobalSKTypeface(...)` 在应用启动时统一注册，所有图表的默认字体即刻生效。
- **增强 `CjkPaint` 辅助方法**：同时设置 `SKTypeface`、`FontFamily`（中文字体名）以及 `IsAntialias=true`，保证 `LabelsPaint`、`Fill`、`Stroke`、`GeometryFill` 等任何进入 `SolidColorPaint` 子类的字体相关字段都被正确覆盖。
- **启用高质量渲染**：在 `CjkPaint` 中同时设置 `Paint.SKFontStyle = SKFontStyle.Normal` 与 `SKPaint.LcdRenderText = true`（如 API 可用），并尝试 `Edging = SKFontEdging.SubpixelAntialias`；在 LiveCharts 层面 `FontBuilder` 中应用同样的高清策略。
- **增大关键图表的标签字号**：将 10/11px 的轴标签/图例统一提升到 12-13px（不破坏布局的前提下），便于 1920×1080 屏幕清晰识别。
- **图例自动换行 + LabelMaxWidth**：为饼图图例配置 `LegendTextPaint` + `WrapLegend`（如 LiveChartsCore 2.x 支持），并增大饼图卡片内边距。
- **雷达图轴标签优化**：调整 `OuterRadius` / `InnerRadius` / `LabelAngle` 让 12 个 KillChain 轴标签（"侦察 / 初始访问 / …"）不被裁切。
- **柱状图 X 轴标签旋转**：当分类数 ≥ 4 时启用 `LabelsRotation` 让长标签（如 "P0 立即" "P1 紧急"）横向完整显示。
- **兜底字体回退**：通过 `SKFontManager.Default.MatchCharacter('汉')` 主动寻找系统中可用的中文字体（如 Microsoft YaHei、SimHei、Noto Sans CJK、Source Han Sans），避免 `SKTypeface.FromFamilyName` 名称不匹配时静默回退到 `SKTypeface.Default`。
- **将可执行文件所在目录作为启动目录**：在 WPF 应用启动入口添加 `Environment.CurrentDirectory = AppContext.BaseDirectory`，避免 LiveChartsCore/SkiaSharp 在字体加载时尝试访问相对路径下的资源。
- **在 `MainWindow.xaml` 根 `Window` 上声明 `TextElement.FontFamily`** 兜底（防止子控件未继承），并将 `AiRiskDashboardRoot` 的重复声明移除。
- **增加字体调试入口**：开发模式下输出当前选中的字体族名到日志，便于诊断字体回退失败的情况。
- **重新发布 `publish-v1.0.1.5`**，启动后 AI 风险评估 Tab 所有图表（含图例、刻度、标签、中心数字、雷达图轴标签、Tooltip）的中文必须清晰可见。

## Impact
- Affected specs: `redesign-ai-risk-assessment-v2`（仪表盘 UI 沿用，但字体注入方式需升级）
- Affected code:
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml`（根 Window 字体声明）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/MainWindow.xaml.cs`（`CjkPaint`、`ResolveChineseTypeface`、图表构建方法）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/App.xaml.cs` 或 `Program.cs`（启动时注册全局字体 + 工作目录）
  - `NetSecurityScanner/src/NetSecurityScanner.Desktop/NetSecurityScanner.Desktop.csproj`（依赖确认 LiveChartsCore ≥ 2.0.0-rc5）

## ADDED Requirements

### Requirement: 全局中文字体注册
系统 SHALL 在应用启动阶段通过 `LiveCharts.Configure(config => config.HasGlobalSKTypeface(<chinese typeface>))` 注册全局默认字体，使得所有未显式指定字体的图表组件默认使用中文字体。

#### Scenario: 启动后图表未显式设置字体
- **WHEN** 任意 LiveChartsCore 图表（CartesianChart、PieChart、PolarChart）创建时
- **AND** 该图表的 `Series`/`Axis` 等未显式指定 `SKTypeface`
- **THEN** SkiaSharp 渲染的中文文字 SHALL 正常显示（无方框或缺失字形）

### Requirement: 显式 CJK 画笔
系统 SHALL 提供 `CjkPaint` 辅助方法用于创建带中文字体的 `SolidColorPaint`，至少同时设置 `SKTypeface`、`FontFamily` 与 `IsAntialias=true` 三项。

#### Scenario: 任意图表属性赋值 CjkPaint
- **WHEN** 调用 `CjkPaint(SKColor.Parse("#xxx"))` 并赋给 `Fill`/`Stroke`/`LabelsPaint`/`GeometryFill`/`GeometryStroke` 等任意属性
- **THEN** 该 Paint 绘制出的所有文字 SHALL 使用中文字体
- **AND** 反锯齿 SHALL 启用

### Requirement: 中文字体自动解析
系统 SHALL 按候选顺序自动解析系统可用的中文字体（Microsoft YaHei UI → Microsoft YaHei → SimHei → SimSun → Noto Sans CJK SC → Source Han Sans SC → PingFang SC），任一命中即返回对应 `SKTypeface`。所有候选均失败时 SHALL 退而使用 `SKFontManager.Default.MatchCharacter('汉')` 寻找系统中能渲染汉字的字体；最终兜底为 `SKTypeface.Default`。

#### Scenario: 系统缺少首选字体
- **WHEN** `SKTypeface.FromFamilyName("Microsoft YaHei UI")` 返回 `null` 或族名为空
- **THEN** 解析器 SHALL 顺序尝试下一个候选
- **AND** 全部失败时 SHALL 使用 `SKFontManager.Default.MatchCharacter('汉')`

### Requirement: 字体解析器必须返回验证过的字形
字体解析器 SHALL 使用 `SKFontManager.Default.MatchFamily(name)` 返回的 `SKTypeface` 实例（而非 `SKTypeface.FromFamilyName(name)`），因为后者在候选字体不存在时仅返回一个族名为空或不正确的默认字形，无法保证包含中文字符。

#### Scenario: 候选字体仅通过名称存在但实际无字形
- **WHEN** `SKTypeface.FromFamilyName("Microsoft YaHei UI")` 返回一个 `FamilyName` 为 "Microsoft YaHei UI" 但实际不含中文字形的 `SKTypeface`（常见于容器化/精简 Windows 环境）
- **AND** `SKFontManager.Default.MatchFamily("Microsoft YaHei UI")` 成功返回有效字形
- **THEN** 解析器 SHALL 返回 `match` 实例而非 `tf` 实例
- **AND** 后续 `SKPaint` 渲染 SHALL 命中真实中文字形（不出现方框）

### Requirement: 启动目录规范化
WPF 应用启动入口 SHALL 将 `Environment.CurrentDirectory` 设置为 `AppContext.BaseDirectory`，确保 LiveChartsCore/SkiaSharp 加载字体或资源时使用绝对路径。

#### Scenario: 应用以非 EXE 目录启动
- **WHEN** 用户从命令行在其他目录执行 `NetSecurityScanner.Desktop.exe`
- **THEN** SkiaSharp SHALL 仍能正常加载内置字体（无 `Could not find family name` 或 IO 异常）

### Requirement: 字体调试日志
系统 SHALL 在 Debug 构建下输出当前选中的中文字体族名到 `System.Diagnostics.Debug.WriteLine`，便于快速诊断字体回退失败的情况。

#### Scenario: 应用启动
- **WHEN** 应用启动阶段完成全局字体注册
- **THEN** Debug 输出 SHALL 包含形如 `[AI Risk Font] Selected CJK typeface: Microsoft YaHei UI (family=Microsoft YaHei UI)` 的日志

### Requirement: 图表文字高清渲染
系统 SHALL 在 `CjkPaint` 与 `LiveCharts.Configure` 的 `FontBuilder` 中启用 SkiaSharp 的亚像素抗锯齿（`LcdRenderText = true` / `Edging = SubpixelAntialias`），使白底背景下的中文字体边缘清晰锐利。

#### Scenario: 1x 缩放白底背景
- **WHEN** AI 风险评估 Tab 在 Windows 缩放 100% 下渲染
- **THEN** 所有图表文字 SHALL 边缘平滑（无明显阶梯锯齿）

### Requirement: 图表文字字号最小可读
系统 SHALL 将所有图表的轴标签、图例、刻度文字的 `TextSize` 统一设置为 ≥ 11px（关键标签 12-13px），确保 1920×1080 屏幕默认缩放下文字清晰可读。

#### Scenario: 雷达图 12 个 KillChain 轴标签
- **WHEN** `BuildKillChainChart` 渲染时
- **THEN** 12 个轴标签的 `TextSize` SHALL ≥ 11px
- **AND** 标签完整可见（不被内圈/外圈裁切）

#### Scenario: 饼图图例
- **WHEN** `BuildServiceTypeChart` / `BuildRiskCategoryChart` 渲染时
- **THEN** 图例文字 `TextSize` SHALL ≥ 12px
- **AND** 图例项完整可见（不被卡片右边缘裁切）

#### Scenario: 柱状图 X 轴标签
- **WHEN** `BuildCveSeverityChart` / `BuildRemediationChart` 渲染时
- **THEN** X 轴标签 `TextSize` SHALL ≥ 11px
- **AND** 长标签（如 "P0 立即"）通过 `LabelsRotation` 或扩大行高避免与轴线重叠

### Requirement: 雷达图轴标签不裁切
系统 SHALL 在 `BuildKillChainChart` / `BuildDimensionalChart` 中合理设置 `TotalAngle`、`InnerRadius`、`OuterRadius`，并结合 `PolarChart` 控件的 `Padding`，让 10-12 个中文轴标签完整显示在卡片范围内。

#### Scenario: 12 轴标签雷达
- **WHEN** `BuildKillChainChart` 渲染 12 个轴（侦察/初始访问/…/影响）
- **THEN** 所有轴标签 SHALL 完整可见（不与相邻标签重叠、不被裁切）

### Requirement: 柱状图 X 轴标签不重叠
系统 SHALL 对分类数 ≥ 4 的柱状图启用 `LabelsRotation` 或适当增大行高，确保长标签（如 "P0 立即"）横向完整显示。

#### Scenario: 修复优先级柱状图
- **WHEN** `BuildRemediationChart` 渲染 5 个分类（"P0 立即"/"P1 紧急"/…/"P4 低"）
- **THEN** X 轴标签 SHALL 不重叠、不与轴线重叠

### Requirement: 关键发现列表文字清晰
系统 SHALL 在 `ItemsControl` 的 `DataTemplate` 中显式声明 `TextElement.FontFamily`，防止列表项回退到默认字体。

#### Scenario: 关键发现列表渲染
- **WHEN** `AiRiskKeyFindingsList` 显示带中文的发现条目
- **THEN** 每条 TextBlock SHALL 使用中文字体（不出现 □□□□）

### Requirement: 饼图图例使用 CJK 字体画笔
系统 SHALL 在 `BuildServiceTypeChart` 与 `BuildCategoryChart` 中为 `PieChart.LegendTextPaint` 显式设置 CjkPaint，避免图例文字回退到不含中文字形的默认 Paint。

#### Scenario: 饼图渲染
- **WHEN** `AiRiskServiceTypeChart` 或 `AiRiskCategoryChart` 渲染图例（如 "HTTP / HTTPS / SSH / RDP" 或 "CVE 漏洞 / 配置风险 / 服务暴露"）
- **THEN** 图例文字 SHALL 使用中文字体（不出现 □□□□）
- **AND** 图例字号 SHALL ≥ 12px

### Requirement: 图表 Tooltip 使用 CJK 字体画笔
系统 SHALL 为所有 `CartesianChart` / `PieChart` / `PolarChart` 设置 `TooltipTextPaint`（含 CJK 字体），避免鼠标悬停时的 Tooltip 文字出现方框。

#### Scenario: 鼠标悬停在柱状图/饼图扇区/雷达图节点上
- **WHEN** 用户将鼠标悬停在任一图表数据点上
- **THEN** 弹出的 Tooltip 文字 SHALL 使用中文字体
- **AND** Tooltip 背景 SHALL 为半透明白色（与白色卡片主题一致）

### Requirement: 关键标签进一步放大
对于"综合风险评分"中心数字、"10 维安全评分雷达"轴标签、"修复优先级"X 轴标签这三类用户最关注的信息，系统 SHALL 将 `TextSize` 提升至 13-14px（在 1920×1080 默认缩放下清晰可读）。

#### Scenario: 中心数字渲染
- **WHEN** `BuildGaugeChart` 渲染综合评分时
- **THEN** 等级描述文字（"极度危险 / 高风险 / 中等风险 / 安全"） SHALL `TextSize` ≥ 13px

#### Scenario: 雷达图轴标签
- **WHEN** `BuildKillChainChart` 渲染 8 个 KillChain 阶段
- **THEN** 8 个轴标签的 `TextSize` SHALL = 13px

### Requirement: 雷达图标签角度优化
系统 SHALL 在 `PolarChart` 控件的 XAML 中为 `KillChain` 雷达图设置 `OuterRadius`（避免标签被外圈裁切），并为 `BuildKillChainChart` 的 `PolarAxis` 设置 `LabelsAlignment` 让长标签（如 "初始访问"）根据角度自动调整位置。

#### Scenario: 8 阶段 KillChain 雷达
- **WHEN** `BuildKillChainChart` 渲染 "侦察 / 初始访问 / 执行 / 提权 / 凭据访问 / 发现 / 横向移动 / 影响"
- **THEN** 所有标签 SHALL 在卡片范围内完整可见
- **AND** 标签 SHALL 沿径向方向对齐，避免与相邻轴标签重叠

### Requirement: 内嵌字体兜底（仅在系统无 CJK 字体时启用）
系统 SHALL 在无法解析任何系统中文字体时，回退到内嵌的 `Noto Sans CJK SC` 或 `Source Han Sans SC` 字体文件（作为应用资源打包）。该资源 SHALL 通过 `<Resource Include="..." />` 添加，并在 `CjkFontResolver` 中通过 `SKTypeface.FromFile(...)` 加载。

#### Scenario: 运行环境无任何中文字体
- **WHEN** `SKFontManager.Default.MatchCharacter('汉')` 也返回 null（极端精简环境）
- **THEN** 解析器 SHALL 尝试加载内嵌 `NotoSansSC-Regular.otf`
- **AND** 中文 SHALL 仍能正常显示（不出现方框）

## MODIFIED Requirements

### Requirement: 图表构建中所有文字画笔均使用中文字体
（来源 `redesign-ai-risk-assessment-v2` 中构建图表的方法）所有图表（`BuildCveSeverityChart` / `BuildServiceTypeChart` / `BuildDimensionalChart` / `BuildRemediationChart` / `BuildRiskCategoryChart` / `BuildKillChainChart` / `BuildRiskGaugeChart`）中涉及文字的 `Paint`（`LabelsPaint` / `Fill` / `Stroke` / `GeometryFill` / `GeometryStroke` / `LegendTextPaint` / `TooltipTextPaint`）必须通过 `CjkPaint(...)` 创建，禁止出现直接的 `new SolidColorPaint(...)`（除 `CjkPaint` 内部实现外）。已完成本轮替换，需验证。

## REMOVED Requirements
（无）

## Validation Strategy
1. 编译 `NetSecurityScanner.Desktop` 通过 `dotnet build -c Release` 无错误。
2. 发布到 `publish-v1.0.1.5`，确认 `LiveChartsCore.SkiaSharpView.WPF.dll`、`SkiaSharp.dll`、`libSkiaSharp.dll`、`HarfBuzzSharp.dll`、`libHarfBuzzSharp.dll` 均存在。
3. 启动 `NetSecurityScanner.Desktop.exe`，切到 "AI 风险评估" Tab；目视确认：
   - 风险类别分布饼图图例（"CVE 漏洞"、"配置风险"、"服务暴露"等）显示完整中文
   - 雷达图 12 个轴标签（"侦察 / 初始访问 / 执行 / 持久化 / 权限提升 …"）显示完整中文
   - 修复优先级柱状图 X 轴标签（"P0 立即 / P1 紧急 / P2 高 / P3 中 / P4 低"）显示完整中文
   - 中心综合评分卡片 "极度危险 / 高风险 / 中等风险 / 安全" 等描述显示完整中文
4. 在不同 Windows 容器（无 Microsoft YaHei 的环境）下，验证 `SKFontManager.Default.MatchCharacter('汉')` 兜底仍能让中文显示（不会退化为方框）。
5. 启动时 Debug 输出包含实际选中的字体族名。
6. 视觉增强验证：
   - 图表文字抗锯齿清晰（在白底背景上 1x 缩放下无明显锯齿）
   - 饼图图例完整可见（不被卡片边缘裁切）
   - 雷达图所有轴标签完整可见（不被内圈或外圈裁切）
   - 柱状图 X 轴标签完整显示（不与轴线重叠、不错位）

## Non-Goals
- 不修改 AI 风险评估的业务逻辑与数据模型。
- 不引入第三方字体文件作为内嵌资源（如确有必要在后续 Spec 单独处理）。
- 不修改 AI 风险评估之外的其他 Tab 图表（端口扫描、漏洞扫描、扫描历史等若存在类似问题，单独提 Spec）。
