# 完善注册功能 — 设计

**日期**：2026-06-12
**目标**：增强注册窗口与待审核窗口的可用性 + 修复待审核显示问题

## 1. 数据模型扩展（`Models/User.cs`）

在 `User` 类中新增 3 个选填字段（均使用 `string?`，旧数据反序列化为 null）：

| 字段 | 类型 | 校验 | 唯一 |
|------|------|------|------|
| `Email` | `string?` | 邮箱格式（`@` 且包含 `.`） | 是 |
| `Phone` | `string?` | 11 位数字（1 开头） | 是 |
| `Reason` | `string?` | ≤200 字符 | 否 |

JSON 兼容：新增字段对旧 `users.json` 不影响（缺字段 → null）。

## 2. AuthService 扩展

### 2.1 新增方法

```csharp
// 用户名查重（轻量级，O(N)）
public bool IsUsernameAvailable(string username);

// 邮箱查重
public bool IsEmailAvailable(string? email);

// 手机查重
public bool IsPhoneAvailable(string? phone);

// 计算密码强度（0-100：0=弱，50=中，100=强）
public static int CalcPasswordStrength(string password);

// 邮箱格式校验
public static bool IsValidEmail(string? email);

// 手机格式校验（中国大陆 11 位）
public static bool IsValidPhone(string? phone);
```

### 2.2 修改 `RegisterAsync` 签名

```csharp
public async Task<RegisterResult> RegisterAsync(
    string username, string password,
    string? displayName = null,
    string? email = null,
    string? phone = null,
    string? reason = null);
```

返回类型从 `Task<bool>` 改为 `Task<RegisterResult>`，携带失败原因：
- `Success`（bool）
- `ErrorCode`：`Ok` / `InvalidUsername` / `InvalidPassword` / `InvalidEmail` / `InvalidPhone` / `EmailTaken` / `PhoneTaken` / `UsernameTaken`
- `Message`（string）

## 3. RegisterWindow.xaml 重构

字段顺序（自上而下）：

1. **用户名** (必填)
   - 实时查重：输入满 3 字符后调用 `IsUsernameAvailable`
   - 右侧状态：✅ 可用 / ❌ 已被占用
2. **显示名** (选填)
3. **邮箱** (选填)
   - 实时格式校验 + 查重
   - 右侧状态：✅ 可用 / ❌ 格式错误 / ❌ 已被注册
4. **手机** (选填)
   - 实时格式校验 + 查重
5. **申请说明** (选填，多行 TextBox)
   - ≤200 字符计数提示
6. **密码** (必填)
   - ≥6 位 + 字母+数字（**仅校验强度，不强制拦截**）
   - 下方密码强度条：弱/中/强 + 进度条颜色（红/橙/绿）
7. **确认密码** (必填)
   - 实时比对密码

提交时一次性校验所有必填项，错误统一用红字提示，弱密码**不阻止**注册。

## 4. UserApprovalWindow.xaml 增强

DataGrid 新增 3 列：
- **邮箱** (显示 Email 或 "—")
- **手机** (显示 Phone 或 "—")
- **申请说明** (截断 30 字符 + Tooltip 完整显示)

## 5. PendingUserItem 扩展

`Views/Views/UserApprovalWindow.xaml.cs` 内 `PendingUserItem` 类新增：
- `Email` (string)
- `Phone` (string)
- `Reason` (string)
- `FromUser` 工厂方法从 `User` 复制新字段

## 6. 待审核显示 bug（已修复，仅验证）

- ✅ `DataPaths` 集中化（`%LOCALAPPDATA%\NetSecurityScanner\data\`）
- ✅ `AuthService` / `AssetManagementService` 使用 `DataPaths`
- ✅ 强制重建 WPF Core.dll（11:20:46）
- ✅ 旧 `bin\users.json` 已删除
- ✅ DiagPending 用同一份 Core.dll 验证 6 个待审可读
- **用户操作**：彻底关闭 WPF，重启后 admin/123456 登录，状态栏应显示"⏳ 有 6 个待审用户"

## 7. 测试

### 7.1 单元/集成测试
- 扩展 `AuthSmokeTest`：增加 8 个用例（邮箱/手机/申请说明 注册成功 + 重复拒绝 + 格式校验）
- 扩展 `RolePermissionSmokeTest`：用新字段注册后 admin 审核可看到

### 7.2 手动验证
- 注册带邮箱+手机+说明的账号
- admin 审核窗口看到新字段
- admin 勾选权限 → 批准
- 用户用新账号登录，使用分配权限

## 8. 文件变更清单

| 文件 | 变更 |
|------|------|
| `Models/User.cs` | +3 字段 (Email/Phone/Reason) |
| `Services/AuthService.cs` | +6 方法、RegisterAsync 改签名 |
| `Services/RegisterResult.cs` | 新建（返回结果封装） |
| `Views/Views/RegisterWindow.xaml` | 重构表单 + 强度条 |
| `Views/Views/RegisterWindow.xaml.cs` | +实时校验 + 查重 |
| `Views/Views/UserApprovalWindow.xaml` | +3 列 |
| `Views/Views/UserApprovalWindow.xaml.cs` | +PendingUserItem 新字段 |
| `AuthSmokeTest/Program.cs` | +8 用例 |
| `DiagPending/Program.cs` | 扩展验证新字段 |

## 9. 范围外（明确不做）

- 不实现图形验证码
- 不实现邮件/短信通知
- 不实现邀请码注册
- 不实现 SSO / OAuth
- 不实现密码可见切换（先用 PasswordChar=●，如需要再加）
