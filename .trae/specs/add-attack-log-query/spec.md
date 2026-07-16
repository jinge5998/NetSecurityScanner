# 攻击日志查询功能规范

## Why
当前"分析"菜单缺少从服务器日志中查询被攻击记录的功能。安全管理员需要能够快速查看和分析服务器收到的攻击日志，包括攻击来源IP、攻击目标IP、攻击类型、时间等信息，以便进行安全分析和溯源。

## What Changes
- 在"分析"菜单中新增"攻击日志"选项
- 创建攻击日志查询窗口
- 实现从服务器日志文件解析攻击记录
- 支持按时间范围、攻击类型、来源IP、目标IP进行筛选
- 攻击日志数据表格展示（时间、来源IP、目标IP、攻击类型、风险等级、详情）
- 支持攻击日志导出（CSV、Excel格式）
- 支持攻击来源地理位置分析（可选）
- 攻击统计面板（攻击总数、按类型统计、按IP统计）

## Impact
- Affected specs: 分析菜单功能
- Affected code: MainWindow.xaml.cs（添加菜单项）, 新建AttackLogWindow.xaml/cs, 新建AttackLogService.cs

## ADDED Requirements

### Requirement: 攻击日志菜单
The system shall在"分析"菜单中添加"攻击日志"选项，点击后打开攻击日志查询窗口。

#### Scenario: 用户点击菜单项
- **WHEN** 用户点击"分析" > "攻击日志"菜单项
- **THEN** 打开AttackLogWindow窗口，自动加载最近的攻击日志

### Requirement: 攻击日志解析
The system shall支持从服务器日志文件中解析攻击记录，包括：
- Windows事件日志（Security Log）
- Web服务器日志（IIS/Apache/Nginx访问日志、错误日志）
- 防火墙日志
- 自定义日志文件路径

#### Scenario: 加载攻击日志
- **WHEN** 窗口打开或用户点击"刷新"按钮
- **THEN** 从配置的日志源加载攻击记录，显示在数据表格中

### Requirement: 攻击日志显示
The system shall以表格形式显示攻击日志，每行包含：
- 时间戳（攻击发生时间）
- 来源IP（攻击者IP地址）
- 目标IP（被攻击服务器IP地址）
- 攻击类型（SQL注入、XSS、暴力破解、端口扫描、DDoS等）
- 风险等级（高/中/低）
- 请求URL/端口（被攻击的资源）
- 状态码/响应结果
- 详情描述

#### Scenario: 查看攻击日志列表
- **WHEN** 攻击日志加载完成
- **THEN** 按时间倒序显示在数据表格中，最新的攻击记录在顶部

### Requirement: 搜索和筛选
The system shall提供以下筛选功能：
- 时间范围筛选（今天/最近7天/最近30天/自定义日期范围）
- 攻击类型筛选（全部/SQL注入/XSS/暴力破解/端口扫描/DDoS/其他）
- 风险等级筛选（全部/高/中/低）
- 来源IP搜索（支持模糊搜索）
- 目标IP搜索（支持模糊搜索）

#### Scenario: 筛选攻击日志
- **WHEN** 用户选择时间范围和攻击类型
- **THEN** 表格仅显示符合条件的攻击记录

### Requirement: 攻击统计面板
The system shall在窗口右侧或底部显示攻击统计信息：
- 攻击总数
- 按攻击类型统计（柱状图或饼图）
- Top 10攻击来源IP（按攻击次数排序）
- Top 10被攻击目标IP
- 攻击趋势（按时间分布）

#### Scenario: 查看统计信息
- **WHEN** 攻击日志加载或筛选后
- **THEN** 统计面板实时更新显示统计结果

### Requirement: 导出功能
The system shall支持导出攻击日志为：
- CSV格式
- Excel格式（.xlsx）
- PDF格式（可选）

#### Scenario: 导出攻击日志
- **WHEN** 用户点击"导出"按钮
- **THEN** 弹出对话框选择保存路径和格式，导出当前筛选的结果

### Requirement: 攻击详情查看
The system shall支持双击攻击日志行查看详细信息，包括：
- 完整请求头信息
- 完整请求体
- 完整响应内容
- 原始日志行

#### Scenario: 查看攻击详情
- **WHEN** 用户双击攻击日志行
- **THEN** 弹出详情窗口显示该攻击的完整信息

### Requirement: 攻击来源地理位置
The system shall支持根据IP地址查询攻击来源的地理位置（国家、省份、城市），并在详情中显示。

#### Scenario: 查看攻击来源位置
- **WHEN** 用户查看攻击详情
- **THEN** 显示攻击来源IP的地理位置信息

## MODIFIED Requirements

### Requirement: "分析"菜单
**修改原因**: 需要在"分析"菜单中新增"攻击日志"选项。

**完整修改内容**:
- 在MainWindow.xaml的"分析"菜单中添加分隔符和"攻击日志"菜单项
- 添加菜单点击事件处理

## REMOVED Requirements
无移除需求。
