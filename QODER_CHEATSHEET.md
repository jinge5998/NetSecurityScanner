# Qoder编程规则速查表

## 安全编程模式

### 空值检查
```csharp
// 安全属性访问
obj?.Property?.SubProperty ?? defaultValue

// 安全方法调用
if (obj != null) obj.Method()

// 安全集合访问
collection?.ToList() ?? new List<Item>()
```

### 类型转换
```csharp
// 安全类型转换
if (obj is SomeType typedObj) { /* use typedObj */ }

// 使用as操作符
var result = obj as SomeType ?? defaultValue;

// 安全解析
int.TryParse(input, out var value) ? value : defaultValue
```

### 枚举处理
```csharp
// 安全枚举解析
Enum.TryParse<InputType>(input, out var enumValue) ? enumValue : DefaultType
```

### UI控件访问
```csharp
// 安全访问WPF控件
if (control != null) control.Property = value;

// 安全DataGrid数据绑定
var source = grid.ItemsSource as IEnumerable<Item> ?? Enumerable.Empty<Item>();
```

## 异常处理

### 基本异常处理
```csharp
try 
{
    // 可能出错的代码
}
catch (Exception ex)
{
    // 记录错误
    LogError(ex);
    // 用户友好的错误消息
    MessageBox.Show($"操作失败: {ex.Message}");
}
```

### 异步异常处理
```csharp
try
{
    await SomeAsyncOperation();
}
catch (Exception ex)
{
    HandleAsyncError(ex);
}
```

## 资源管理

### 使用using语句
```csharp
using (var resource = new Resource())
{
    // 使用资源
}
```

## 验证清单

### 修改代码前
- [ ] 备份相关文件
- [ ] 理解代码上下文
- [ ] 识别潜在风险点

### 修改代码后
- [ ] 编译验证
- [ ] 功能测试
- [ ] 错误处理测试
- [ ] 现有功能回归测试

## 调试步骤

1. **重现问题** - 找到触发错误的具体操作
2. **定位错误** - 使用调试工具找到错误位置
3. **分析原因** - 理解错误的根本原因
4. **设计修复** - 制定安全的修复方案
5. **实施修复** - 应用修复并验证
6. **回归测试** - 确认没有引入新问题

## 项目特定注意事项

### 网络安全工具
- 所有扫描必须在授权范围内进行
- 实现适当的速率限制
- 记录所有扫描活动

### WPF应用
- UI更新必须在UI线程上执行
- 使用Dispatcher.Invoke进行跨线程调用
- 注意数据绑定的生命周期

### 性能考虑
- 使用异步操作避免UI冻结
- 实现适当的缓存
- 优化数据库查询