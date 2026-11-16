using System.Collections.Generic;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 系统权限位常量。
    /// 使用字符串存储（可读性 / 可扩展性优于位运算）。
    /// </summary>
    public static class Permission
    {
        public const string AssetView = "Asset:View";
        public const string AssetAdd = "Asset:Add";
        public const string AssetEdit = "Asset:Edit";
        public const string AssetDelete = "Asset:Delete";
        public const string AssetImport = "Asset:Import";
        public const string AssetExport = "Asset:Export";

        public const string UserView = "User:View";
        public const string UserManage = "User:Manage";

        public const string ScanRun = "Scan:Run";
        public const string ReportExport = "Report:Export";

        public static readonly IReadOnlyList<string> AllPermissions = new[]
        {
            AssetView, AssetAdd, AssetEdit, AssetDelete, AssetImport, AssetExport,
            UserView, UserManage,
            ScanRun, ReportExport
        };

        public static readonly IReadOnlyList<string> AllPermissionLabels = new[]
        {
            "资产查看", "资产添加", "资产编辑", "资产删除", "资产导入", "资产导出",
            "用户查看", "用户管理",
            "发起扫描", "导出报告"
        };

        /// <summary>
        /// 预置权限模板（admin 一键批量授予）。
        /// </summary>
        public static class Templates
        {
            public const string Viewer = "Viewer";
            public const string Operator = "Operator";
            public const string AssetManager = "AssetManager";

            public static readonly Dictionary<string, (string Label, string Description, IReadOnlyList<string> Permissions)> All = new()
            {
                [Viewer] = (
                    "👁 仅查看",
                    "仅可查看资产列表和详情，不能修改",
                    new[] { AssetView }),

                [Operator] = (
                    "🛠 普通操作员",
                    "可查看、添加、编辑资产，不能删除",
                    new[] { AssetView, AssetAdd, AssetEdit, ScanRun }),

                [AssetManager] = (
                    "📋 资产管理员",
                    "可管理资产全流程（查看/增/改/删/导入/导出）",
                    new[] { AssetView, AssetAdd, AssetEdit, AssetDelete, AssetImport, AssetExport, ScanRun, ReportExport })
            };
        }
    }
}
