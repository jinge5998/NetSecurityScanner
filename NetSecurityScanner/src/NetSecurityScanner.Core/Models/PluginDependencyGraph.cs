using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件依赖图节点（v6 由 VersionManager.ResolveDependencyAsync 构造）
    /// </summary>
    public class PluginDependencyNode
    {
        public string PluginId { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public DependencyStatus Status { get; set; } = DependencyStatus.Satisfied;
        public string MinRequiredVersion { get; set; } = string.Empty;
        public List<PluginDependencyNode> Children { get; set; } = new();
    }

    public enum DependencyStatus
    {
        Satisfied = 0,     // 绿：已安装且版本满足
        Missing = 1,       // 红：未安装
        VersionTooLow = 2  // 黄：已安装但版本低于要求
    }

    public class PluginDependencyGraph
    {
        public PluginDependencyNode Root { get; set; } = new();
        public List<string> MissingDependencies { get; set; } = new();
    }
}
