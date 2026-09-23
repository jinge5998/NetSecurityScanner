# NMAP 模板功能增强 Spec

## Why
专家模式现有 14 个 NMAP 模板按钮（8 个 NMAP 内置 + 6 个业务场景预设），但存在以下缺陷：
1. `PresetStealthBtn_Click` 使用 `RandomizeCheckBox`（端口顺序），但 `GenerateNmapCommand` 输出的是 `--randomize-hosts`（目标顺序）— **类型不匹配 bug**
2. 缺失 nmap 官方的 5 个标准模板：Intense Scan、Intense Scan Plus UDP、Regular Scan、Slow Comprehensive Scan、Quick Traceroute
3. 14 个按钮的设置分散在 14 个 hardcoded 方法里，新模板需要复制粘贴 ~15 行代码
4. `GenerateNmapCommand` 缺失 `--version-intensity`、`--osscan-limit`、`-Pn` 等关键 flag
5. 模板通知 emoji 不一致（部分有 🥷💥🔍🖥️🌐📶✅👻，部分无）
6. 模板应用前用户无法预览实际 nmap 命令行
7. 用户无法保存自己的自定义参数组合为"我的模板"

## What Changes
- **NEW**: 数据驱动模板定义 `NmapTemplate` 类 + 静态注册表 `NmapTemplateRegistry` — 单一源定义所有模板
- **NEW**: 新增 5 个标准 nmap 模板按钮（行 1944 后追加）
- **NEW**: 自定义模板保存/加载功能（保存到 `%LOCALAPPDATA%\NetSecurityScanner\nmap_templates.json`）
- **FIX**: `PresetStealthBtn` 改用 `RandomTargetOrderCheckBox`（与 `--randomize-hosts` 一致）
- **FIX**: `GenerateNmapCommand` 补全 `--version-intensity`、`--osscan-limit`、`-Pn`、`--open`、`--min-rate`
- **ENHANCE**: XAML 增加"模板预览"面板（点击模板显示该模板对应的完整 nmap 命令）
- **POLISH**: 所有模板通知统一 emoji 前缀

## Impact
- Affected specs: 专家模式扫描配置 UI
- Affected code:
  - `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\Views\Views\ExpertModeWindow.xaml.cs`（14 个模板按钮方法重构 + 1 个 bug 修复 + 5 个新按钮 + 1 个预览面板）
  - `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Desktop\Views\Views\ExpertModeWindow.xaml`（5 个新按钮 + 预览面板 XAML）
  - `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Core\Models\NmapTemplate.cs`（新文件）
  - `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Core\Services\NmapTemplateRegistry.cs`（新文件）
  - `d:\360安全浏览器下载\软件开发备份\网络安全漏洞扫描\NetSecurityScanner\src\NetSecurityScanner.Core\Services\CustomNmapTemplateStore.cs`（新文件）

## ADDED Requirements

### Requirement: NmapTemplate 数据模型
`System SHALL provide` 一个 `NmapTemplate` 数据类，包含 `Id`、`Name`、`Icon`、`Description`、`NmapCommand`、`Apply(ExpertModeWindow)` 方法（将所有扫描设置应用到 UI 控件）。
`System SHALL provide` 静态注册表 `NmapTemplateRegistry` 持有所有内置模板的列表（14 + 5 = 19 个）。

#### Scenario: 模板应用到 UI
- **WHEN** 用户点击任意 NMAP 模板按钮
- **THEN** `NmapTemplate.Apply(window)` 方法被调用，UI 控件值被设置 + `ShowTemplateApplied` 通知 + 预览面板显示该模板的 nmap 命令

#### Scenario: 模板预览
- **WHEN** 用户点击"预览 nmap 命令"按钮
- **THEN** 弹出对话框显示当前 UI 设置对应的完整 nmap 命令行（剪贴板复制按钮）

### Requirement: 5 个新标准模板
`System SHALL provide` 以下 5 个新增 NMAP 模板：
- **Intense Scan** (-T4 -A -v)：T4 时序 + 服务/OS/脚本检测 + 详细输出
- **Intense Scan Plus UDP** (-sS -sU -T4 -A -v)：TCP SYN + UDP 扫描
- **Regular Scan**（默认）：nmap 默认行为
- **Slow Comprehensive Scan** (-sS -sU -T4 -A -v -p- -PE)：全端口全协议综合扫描
- **Quick Traceroute** (-sn --traceroute)：仅主机发现 + 路由追踪

### Requirement: 自定义模板持久化
`System SHALL provide` "保存当前为模板" 按钮 + "我的模板" 下拉/列表。
保存路径：`%LOCALAPPDATA%\NetSecurityScanner\nmap_templates.json`
数据格式：`{ "id": "uuid", "name": "我的模板1", "config": {...ExpertScanConfiguration...} }`

#### Scenario: 保存自定义模板
- **WHEN** 用户配置好参数后点击"💾 保存为模板"
- **THEN** 弹输入框输入模板名 → 保存到 `nmap_templates.json` → "我的模板" 下拉增加一项

#### Scenario: 加载自定义模板
- **WHEN** 用户从"我的模板"下拉选择已保存的模板
- **THEN** 应用该模板的所有设置（端口、并发、超时等）到 UI

#### Scenario: 删除自定义模板
- **WHEN** 用户右键"我的模板"列表项选择"删除"
- **THEN** 从 `nmap_templates.json` 移除该项并刷新下拉

## MODIFIED Requirements

### Requirement: PresetStealthBtn 修复
`ApplyRequireTemplate` 修复：**改用 `RandomTargetOrderCheckBox.IsChecked = true` 而非 `RandomizeCheckBox`**。
理由：nmap `--randomize-hosts` 是目标顺序随机化，不是端口顺序；Task 7.2 已将这两个字段独立化。

### Requirement: GenerateNmapCommand 增强
补全以下 nmap flags：
- `--version-intensity N` (来自 `ServiceIntensityComboBox`)
- `--osscan-limit` (仅当 `OsDetect` + `TcpScan` 时)
- `-Pn` (仅当 `HostDiscovery == false` 时)
- `--open` (仅显示开放端口 - 选项)
- `--min-rate N` (来自 `PacketRate` 当 `RateLimit == true` 时)
- `--stats-every 5s` (进度输出)

## REMOVED Requirements
无。
