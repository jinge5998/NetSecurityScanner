# Linux/Ubuntu 跨平台移植 Spec

## Why

当前 NetSecurityScanner 基于 **WPF（Windows Presentation Foundation）** 框架开发，是纯 Windows 应用。用户需要将软件打包为可在 **Linux/Ubuntu** 系统上直接运行的版本，实现真正的跨平台部署能力。

## What Changes

- **核心UI框架迁移**: 从 WPF 迁移到 **Avalonia UI 11.x**（.NET 最成熟的跨平台桌面框架，支持 Linux/GTK）
- **NuGet 包替换**: 将所有 Windows-only 的依赖包替换为跨平台等价物
- **多目标框架配置**: 项目同时支持 `net8.0-windows`（WPF）和 `net8.0`（Avalonia/Linux）
- **Linux 打包输出**: 生成 AppImage / deb / tar.gz 三种 Linux 分发格式
- **条件编译处理**: 通过 `#if` 预处理器指令隔离平台特定代码

## Impact

- Affected specs: 无直接关联已有 spec，属于新增功能
- Affected code:
  - `NetSecurityScanner.csproj` — 项目文件重构
  - `MainWindow.xaml` + `MainWindow.xaml.cs` — 主窗口迁移到 Avalonia AXAML
  - 所有 `*.xaml` 视图文件 — 从 WPF XAML 转换为 Avalonia AXAML
  - `Services/HistoryReportGenerator.cs` — PDF 生成需适配 Linux 字体路径
  - `Services/ProfessionalPdfReportGenerator.cs` — 同上
  - 所有使用 `System.Windows.*` 命名空间的 `.cs` 文件

## ADDED Requirements

### Requirement: 跨平台 UI 框架迁移

系统 SHALL 使用 **Avalonia UI 11.x** 作为 Linux 平台的 UI 框架，保持与现有 WPF 版本功能对等。

#### Scenario: Linux 上启动程序

- **WHEN** 用户在 Ubuntu 系统上双击运行打包后的可执行文件
- **THEN** 程序以 GTK3 窗口正常显示主界面，包含所有功能标签页（扫描、历史记录、插件管理等）

### Requirement: NuGet 包跨平台替换

| 原 Windows-only 包 | 替代方案 | 说明 |
|---|---|---|
| `OxyPlot.Wpf` | `OxyPlot.SkiaSharp` + Avalonia 绑定 | 图表渲染 |
| `LiveChartsCore.SkiaSharpView.WPF` | `LiveChartsCore.SkiaSharpView.AvaloniaUI` | 数据可视化 |
| `DocX` | `NPOI` 或移除 Word 导出功能 | Word 文档生成 |
| `iTextSharp` (5.5.13) | `QuestPDF` 或 `iText7` | PDF 生成（兼容性更好） |
| `System.Data.SQLite` | `Microsoft.Data.Sqlite` + SQLite 本地库 | 数据库访问 |

#### Scenario: Linux 上生成 PDF 报告

- **WHEN** 用户在 Linux 上选择历史记录并点击"生成报告"→ PDF 格式
- **THEN** 报告成功生成，中文显示正常（使用 Linux 系统字体：Noto Sans CJK / WenQuanYi Micro Hei）

### Requirement: Linux 打包分发格式

系统 SHALL 支持以下三种 Linux 分发格式的构建：

1. **AppImage** (`NetSecurityScanner-x86_64.AppImage`) — 通用便携版，无需安装
2. **deb 包** (`net-security-scanner_1.0.0_amd64.deb`) — Debian/Ubuntu 安装包
3. **tar.gz 归档** (`NetSecurityScanner-Linux-x64.tar.gz`) — 通用压缩包

#### Scenario: 构建并运行 AppImage

- **WHEN** 开发者执行 `dotnet publish` 并用 linuxdeploy 打包为 AppImage
- **THEN** 生成的 `.AppImage` 文件可在任何 x86_64 Linux 发行版上直接运行（chmod +x 后执行）

### Requirement: 条件编译与代码共享

系统 SHALL 使用条件编译指令隔离平台差异，最大化业务逻辑代码复用：

```
共享层（100%复用）:
├── Models/          ← 数据模型
├── Core/            ← 扫描引擎、插件管理器、工作流管理器
├── Data/            ← 数据验证、JSON 处理
├── Utils/           ← 工具类
└── Services/        ← 服务层（除 PDF 字体路径外）

平台层（独立实现）:
├── Views/           ← WPF XAML vs Avalonia AXAML
├── MainWindow       ← 入口点与窗口初始化
└── Program.cs       ← 启动引导逻辑
```

## MODIFIED Requirements

### Requirement: 项目文件结构

将单目标项目改造为**多目标条件编译**项目或**拆分为共享库+平台项目**的解决方案结构。

推荐采用 **"共享库 + 平台壳"** 方案：

```
NetSecurityScanner.sln
├── NetSecurityScanner.Core/         # 共享业务逻辑（netstandard2.0 或 net8.0）
│   ├── Models/
│   ├── Core/
│   ├── Data/
│   ├── Utils/
│   └── Services/
│
├── NetSecurityScanner.Desktop/      # Windows 版本（net8.0-windows, WPF）
│   ├── Views/ (WPF XAML)
│   ├── MainWindow.xaml/.cs
│   └── Program.cs
│
├── NetSecurityScanner.Linux/        # Linux 版本（net8.0, Avalonia）
│   ├── Views/ (Avalonia AXAML)
│   ├── MainWindow.axaml/.axaml.cs
│   └── Program.cs
│
└── NetSecurityScanner.Packaging/    # 打包脚本
    ├── build-appimage.sh
    ├── build-deb.sh
    └── build-targz.sh
```

### Requirement: PDF 报告生成器的字体适配

修改 `HistoryReportGenerator.cs` 和 `ProfessionalPdfReportGenerator.cs` 的字体加载逻辑，支持 Linux 系统字体路径：

```csharp
// Linux 字体优先级
private static readonly string[] LinuxFontPaths = {
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
};
```
