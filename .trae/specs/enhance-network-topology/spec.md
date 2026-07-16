# 网络拓扑可视化增强规范

## 为什么
当前网络拓扑功能（NetworkTopologyWindow）仅以表格形式展示设备列表，缺少直观的图形化拓扑图展示。NetworkTopologyService已经具备设备发现、指纹识别和关系分析能力，但未在UI层面以节点-连线的图形方式呈现，用户体验不够专业和直观。

## 变更内容
- 在NetworkTopologyWindow中添加Canvas-based网络拓扑图渲染区域
- 实现设备节点自动布局算法（力导向布局）
- 实现设备间关系连线绘制（基于NetworkTopologyService的关系分析）
- 支持拓扑图交互：节点拖拽、缩放、点击查看详情
- 修改MainWindow.xaml.cs中的NetworkTopology_Click方法，打开NetworkTopologyWindow而非显示占位提示
- 根据设备类型使用不同的图标和颜色区分节点
- 连线支持显示关系类型标签

## 影响
- 影响规格：网络拓扑可视化能力
- 影响代码：
  - NetworkTopologyWindow.xaml - 添加拓扑图Canvas区域
  - NetworkTopologyWindow.xaml.cs - 添加拓扑图渲染和交互逻辑
  - MainWindow.xaml.cs - 修改NetworkTopology_Click方法
  - NetworkTopologyService.cs - 可能需要补充关系分析数据

## 新增需求

### 需求：网络拓扑图可视化
系统 SHALL 提供图形化的网络拓扑展示，以节点和连线的方式直观显示网络设备和它们之间的关系。

#### 场景：成功展示拓扑图
- **当** 用户点击"网络拓扑"菜单项
- **那么** 打开NetworkTopologyWindow，包含拓扑图Canvas区域
- **当** 网络扫描完成后
- **那么** 拓扑图上自动绘制设备节点和关系连线

### 需求：设备节点可视化
系统 SHALL 根据设备类型使用不同的图标和颜色渲染设备节点。

#### 场景：设备类型区分
- **当** 拓扑图渲染设备节点时
- **那么** Windows服务器显示为蓝色服务器图标，Linux设备显示为绿色，Web服务器显示为橙色等

### 需求：拓扑图交互
系统 SHALL 支持用户对拓扑图进行交互操作。

#### 场景：节点拖拽
- **当** 用户拖拽拓扑图中的节点
- **那么** 节点跟随鼠标移动，其他节点保持不动

#### 场景：查看详情
- **当** 用户双击拓扑图中的节点
- **那么** 显示该设备的详细信息面板

### 需求：菜单集成
系统 SHALL 在点击"网络拓扑"菜单时打开NetworkTopologyWindow。

#### 场景：菜单点击
- **当** 用户点击"分析"菜单中的"网络拓扑"
- **那么** 打开NetworkTopologyWindow实例

## 修改需求

### 需求：NetworkTopologyWindow
原需求：NetworkTopologyWindow仅以表格形式展示设备列表
修改后：NetworkTopologyWindow SHALL 包含左右两个区域，左侧为拓扑图Canvas，右侧为设备列表和数据表格

### 需求：NetworkTopology_Click
原需求：显示"功能开发中"提示框
修改后：打开NetworkTopologyWindow窗口
