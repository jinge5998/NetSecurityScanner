---
trigger: manual
alwaysApply: false
---
# Qoder编程规则使用指南

## 概述

本指南介绍如何在网络安全漏洞扫描工具项目中应用Qoder编程规则，确保代码质量和系统稳定性。

## 规则应用

### 1. 错误处理规则

#### UI控件安全访问
```csharp
// 错误的做法
someControl.Property = value;  // 可能导致NullReferenceException

// 正确的做法
if (someControl != null)
{
    someControl.Property = value;
}
```

#### 安全类型转换
```csharp
// 错误的做法
var result = (SomeType)obj;  // 可能在运行时失败

// 正确的做法
if (obj is SomeType typedObj)
{
    // 使用typedObj
}
// 或者
var result = obj as SomeType ?? defaultValue;
```

#### 安全枚举解析
```csharp
// 安全的枚举解析
if (Enum.TryParse<InputType>(inputString, out var enumValue))
{
    // 使用enumValue
}
else
{
    // 处理解析失败的情况
    enumValue = DefaultInputType;
}
```

#### DataGrid数据源安全访问
```csharp
// 安全访问DataGrid数据源
var itemsSource = dataGrid.ItemsSource as IEnumerable<DataItem> ?? Enumerable.Empty<DataItem>();
foreach (var item in itemsSource)
{
    // 处理数据项
}
```

### 2. 空值安全处理

#### 字符串安全处理
```csharp
// 检查字符串是否为空或空白
if (!string.IsNullOrWhiteSpace(inputString))
{
    // 处理非空字符串
}
```

#### 对象属性安全访问
```csharp
// 安全访问对象属性
var value = obj?.Property?.SubProperty ?? defaultValue;
```

### 3. 异步操作安全处理

#### WPF UI更新
```csharp
// 在UI线程上更新控件
await Dispatcher.InvokeAsync(() =>
{
    someControl.Text = newValue;
});
```

#### 异常处理
```csharp
try
{
    await SomeAsyncOperation();
}
catch (Exception ex)
{
    // 记录错误并通知用户
    LogError(ex);
    MessageBox.Show("操作失败: " + ex.Message, "错误", MessageBoxButton.OK, MessageBoxImage.Error);
}
```

### 4. 资源管理

#### 使用using语句
```csharp
using (var resource = new ManagedResource())
{
    // 使用资源
} // 资源在此处自动释放
```

## 项目特定规则

### 网络安全漏洞扫描工具项目规则

1. **网络扫描安全**：
   - 确保所有扫描功能仅在授权网络中使用
   - 实现适当的速率限制以避免网络拥塞
   - 记录所有扫描活动以供审计

2. **数据安全**：
   - 扫描结果必须安全存储
   - 用户凭据等敏感信息必须加密处理
   - 实现适当的访问控制机制

3. **性能优化**：
   - 使用异步编程模式避免UI冻结
   - 实现适当的缓存机制
   - 优化数据库查询性能

4. **用户体验**：
   - 提供清晰的错误消息
   - 实现进度指示器以显示长时间运行的操作
   - 确保界面响应迅速

## 验证步骤

每次代码修改后，请按以下步骤验证：

1. **编译验证**：确保代码能够成功编译
2. **功能测试**：测试修改的功能是否正常工作
3. **回归测试**：确认现有功能不受影响
4. **错误检查**：验证没有引入新的错误
5. **性能检查**：确保修改没有显著影响性能

## 调试技巧

当遇到错误时，按以下步骤系统性地解决问题：

1. **重现问题**：确定触发错误的具体操作
2. **定位错误**：使用调试工具找到错误发生的具体位置
3. **分析原因**：理解错误的根本原因
4. **设计解决方案**：制定修复计划
5. **实施修复**：应用安全的修复方法
6. **验证修复**：确认错误已被解决且没有引入新问题

## 团队协作

遵循以下协作原则：

- 在修改代码前创建备份
- 使用有意义的提交信息
- 遵循一致的代码风格
- 及时分享知识和最佳实践
- 定期进行代码审查