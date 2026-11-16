using System;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件被黑名单/策略拦截时抛出的异常（v6）
    /// </summary>
    public class PluginBlockedException : Exception
    {
        public string PluginId { get; }
        public PluginBlockedException(string pluginId, string message) : base(message)
        {
            PluginId = pluginId;
        }
    }

    /// <summary>
    /// 插件请求未授权的权限/危险操作时抛出的异常（v6）
    /// </summary>
    public class PermissionDeniedException : Exception
    {
        public string PluginId { get; }
        public string Operation { get; }
        public PermissionDeniedException(string pluginId, string operation, string message) : base(message)
        {
            PluginId = pluginId;
            Operation = operation;
        }
    }

    /// <summary>
    /// v7：插件签名校验失败时抛出
    /// </summary>
    public class PluginSignatureException : Exception
    {
        public string PluginId { get; }
        public string DllPath { get; }
        public string Sha256 { get; }
        public PluginSignatureException(string pluginId, string dllPath, string sha256, string message)
            : base(message)
        {
            PluginId = pluginId;
            DllPath = dllPath;
            Sha256 = sha256;
        }
    }

    /// <summary>
    /// v7：沙箱违规时抛出（越界访问文件/网络/进程/注册表）
    /// </summary>
    public class SandboxViolationException : Exception
    {
        public string PluginId { get; }
        public string Operation { get; }
        public string Target { get; }
        public SandboxViolationException(string pluginId, string operation, string target, string message)
            : base(message)
        {
            PluginId = pluginId;
            Operation = operation;
            Target = target;
        }
    }
}
