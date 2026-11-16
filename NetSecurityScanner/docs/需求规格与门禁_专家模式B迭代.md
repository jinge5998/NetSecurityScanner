# 需求规格与门禁：专家模式续作 B 迭代（US-B1）

- 文档版本：V1.0
- 日期：2026-11-03
- 作者：产品经理 / 项目经理
- 范围：**B**（轻量、确定性收益）—— B1 落地；B2 依据守真原则延期

---

## 1. 决策过程与范围锁定

在契约测试 `ExpertScanConfigEffectivenessContractTests` 的显式归档基础上，专家模式剩余可完善项分三类：

| 类别 | 候选 | 决策 |
|------|------|------|
| A · 真实待修（代价高） | A1 SYN 半开扫描 / A2 OS 检测 | 待用户另行确认范围（需原始套接字/管理员权限） |
| B · 轻量确定收益 | B1 「仅显示开放端口」接线 | **本次落地** |
| B · 轻量确定收益 | B2 Verbosity → 内置引擎日志分级 | **延期（守真）** |
| C · 技术债 | C1 凭据安全（R4） | 未列本次范围 |

- 用户明确选择 **B**。
- **B2 延期理由（依据"零假接线"契约原则）**：内置引擎 `PortScanner` 无日志分级通道，`Verbosity` 当前仅作用于 nmap `-q/-v/-vv`。在 WPF 层不作引擎对接就强行映射，属于"界面可调但引擎不消费"的装饰性假接线，与本项目契约守卫精神冲突。已如实归为待确认项，不做虚构接线。

---

## 2. 用户故事 US-B1

**作为** 使用专家模式的安全管理员，
**我希望** 勾选「仅显示开放端口」后，结果表立即只显示开放端口且该偏好在新扫描/清空/重置后仍保持，
**以便** 不必每次都在结果表做二次右键筛选。

### 验收标准（Given-When-Then）

- GIVEN 存在同时含"开放/关闭"状态端口的扫描结果，WHEN 勾选「仅显示开放端口」，THEN 结果表只显示 `Status=="开放"` 的行。
- GIVEN 已勾选「仅显示开放端口」，WHEN 发起新扫描 / 清空结果 / 点击重置筛选，THEN 该过滤仍自动重放（作为持久偏好保持一致）。
- GIVEN 已勾选「仅显示开放端口」，WHEN 取消勾选，THEN 结果表恢复显示全部行。
- GIVEN 勾选状态下再通过上下文菜单选「高危/严重端口」，WHEN 操作应用，THEN 「仅显示开放端口」自动取消（两者互斥，界面不自我矛盾）。

---

## 3. 设计要点

- 与既有上下文菜单「仅开放」**共用** `_portCategoryFilter` 谓词，新增 `ShowOpenOnlyCheckBox_Checked/_Unchecked` 事件，勾选即 `ApplyPortFilter()`。
- `ResetPortFilters()` 增加对勾选的响应：仍勾选时重放开放过滤，统一新扫描/清空/重置三条路径（[ExpertModeWindow.xaml.cs](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Desktop/Views/Views/ExpertModeWindow.xaml.cs#L4385-L4407)）。
- `FilterOpenPorts_Click` / `FilterHighRiskPorts_Click` 同步勾选状态，保证 UI 与逻辑一致。
- ItemsSource 全程保持同一 `_portResultsView`，绝不替换快照（沿用既有防历史缺陷原则）。
- **Core 契约不变**：ShowOpenOnly 对 Core 引擎仍不参与扫描参数，继续归"仅命令生成"类，但注释已更新为表明 UI 层已接线（[契约测试注释](file:///d:/360安全浏览器下载/软件开发备份/网络安全漏洞扫描/NetSecurityScanner/src/NetSecurityScanner.Core.Tests/ExpertScanConfigEffectivenessContractTests.cs#L112-L116)）。

---

## 4. 质量门禁

- [x] Desktop 编译通过（`dotnet build`，0 错误）
- [x] Core 全量测试通过（**305/305**，0 回归）
- [x] 真实运行验证通过（`APP_RUNNING_OK`，PID 52236）
- [ ] **UI 层行为建议手工冒烟确认**（见 5，纯 WPF 绑定，无 WPF 测试工程）

## 5. 待确认项

- **B2 手工冒烟清单**（纯 UI 行为，需在运行中的应用确认）：
  1. 扫描含开/关端口的网段 → 勾选「仅显示开放端口」→ 确认结果表仅留开放行；
  2. 保持勾选并发起新扫描 → 确认结果仍按开放过滤；
  3. 取消勾选 → 确认恢复全部；
  4. 勾选状态下走上下文「高危」→ 确认「仅显示开放端口」自动取消。

- **后续候选**：A1（SYN 半开扫描，需确认接受管理员权限/防火墙影响）、A2（OS 检测）、C1（凭据安全 R4）。

---

## 6. 项目经理审核结论

- ✅ **通过**（B1 落地 + B2 守真延期记录完整）
- 项目状态：专家模式续作 B 迭代 B1 交付完成，待手工冒烟签收。