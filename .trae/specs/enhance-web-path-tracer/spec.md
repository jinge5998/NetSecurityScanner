# 网页后缀追踪增强 Spec

## Why
当前"网页后缀追踪"功能无法有效追踪远程网页的动态跳转和隐藏路径。主要问题：HTTP重定向链未完整追踪、JS动态跳转检测能力不足、Selenium层ChromeDriver版本兼容性问题导致经常失败、缺少目录爆破和深度爬取能力。需要重新设计为专业的Web路径发现工具。

## What Changes
- 重写 WebPathTracerService.cs 核心追踪逻辑
- 增加 HTTP 重定向链追踪（跟随所有3xx跳转直到最终URL）
- 增加 JS动态跳转深度分析（eval/document.write/混淆代码/SPA路由）
- 增加 ChromeDriver 自动匹配机制（解决版本不兼容问题）
- 增加目录爆破模式（常见路径字典扫描）
- 增加深度爬取模式（递归追踪页面所有链接）
- 重写 WebPathTracerWindow 界面（增加配置选项和结果展示）

## Impact
- Affected code: WebPathTracerService.cs, WebPathTracerWindow.xaml, WebPathTracerWindow.xaml.cs
- Affected NuGet: Selenium.WebDriver, Selenium.WebDriver.ChromeDriver 可能需要更新

## ADDED Requirements

### Requirement: HTTP重定向链完整追踪
系统 SHALL 完整追踪所有HTTP重定向，包括：
- 跟随所有3xx状态码（301/302/303/307/308）直到最终URL
- 记录完整跳转链（每一步的URL、状态码、Location头）
- 检测 Refresh 响应头跳转
- 检测 HTML Meta Refresh 跳转
- 检测 Content-Location 头

#### Scenario: 多级HTTP重定向
- **WHEN** 目标URL经过 A→B→C 三次重定向
- **THEN** 系统记录完整链路 [A(302)→B(301)→C(200)] 并返回最终URL C

### Requirement: JS动态跳转深度分析
系统 SHALL 检测JavaScript动态跳转，包括：
- window.location.href/replace/assign 赋值
- document.location 赋值
- self/top/parent.location 赋值
- setTimeout/setInterval 中的延迟跳转
- eval() 和 new Function() 中的动态代码
- document.write 中的跳转代码
- SPA框架路由（Vue Router / React Router / Angular Router）
- 混淆代码中的跳转（base64编码的URL、十六进制编码）

#### Scenario: SPA路由跳转
- **WHEN** 页面使用 Vue Router 的 router.push('/login') 进行跳转
- **THEN** Selenium层检测到URL变化并记录

### Requirement: ChromeDriver自动匹配
系统 SHALL 自动检测本地Chrome版本并匹配对应ChromeDriver：
- 自动检测 Chrome 安装路径和版本号
- 自动下载匹配版本的 ChromeDriver
- 如果自动匹配失败，提供手动指定路径选项
- 如果Chrome未安装，优雅降级跳过Selenium层

#### Scenario: ChromeDriver版本不匹配
- **WHEN** 本地Chrome版本为121但内置ChromeDriver为120
- **THEN** 系统自动下载121版本ChromeDriver并使用

### Requirement: 目录爆破模式
系统 SHALL 提供目录爆破功能：
- 内置常见Web路径字典（100+条目）
- 支持自定义字典文件
- 多线程并发扫描（可配置并发数）
- 实时显示发现的路径和状态码
- 按状态码分类显示（200/301/403/500等）

#### Scenario: 发现隐藏后台
- **WHEN** 目标 http://example.com 的 /admin/login 返回200
- **THEN** 系统报告发现隐藏路径 /admin/login

### Requirement: 深度爬取模式
系统 SHALL 提供页面深度爬取功能：
- 递归提取页面所有链接（a[href]/form[action]/iframe[src]/link[href]/script[src]）
- 限制爬取深度（默认2层）
- 限制爬取范围（同域/跨域）
- 去重已访问URL
- 按关键词过滤（login/admin/dashboard/api等）

#### Scenario: 发现深层登录页
- **WHEN** 首页链接到 /portal，/portal 链接到 /portal/auth/login
- **THEN** 系统报告发现深层路径 /portal/auth/login

### Requirement: 结果导出
系统 SHALL 支持导出追踪结果：
- 导出为JSON格式
- 导出为TXT格式
- 包含完整的跳转链、发现的路径、敏感文件列表

## MODIFIED Requirements

### Requirement: 追踪流程改进
原流程：第一层→第二层→第三层→第四层（逐层返回第一个结果）
新流程：所有层并行执行，汇总所有发现，按优先级排序展示

### Requirement: 界面改进
- 增加追踪模式选择（快速/标准/深度）
- 增加 ChromeDriver 配置区域
- 增加目录爆破配置（字典选择、并发数）
- 增加结果树形展示
- 增加导出按钮

## REMOVED Requirements
无
