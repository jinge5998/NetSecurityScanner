using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
    /// <summary>
    /// 插件信息模型
    /// </summary>
    public class Plugin
    {
        /// <summary>
        /// 插件ID
        /// </summary>
        public string Id { get; set; }
        
        /// <summary>
        /// 插件名称
        /// </summary>
        public string Name { get; set; }
        
        /// <summary>
        /// 插件描述
        /// </summary>
        public string Description { get; set; }
        
        /// <summary>
        /// 插件版本
        /// </summary>
        public string Version { get; set; }
        
        /// <summary>
        /// 插件作者
        /// </summary>
        public string Author { get; set; }
        
        /// <summary>
        /// 插件类别
        /// </summary>
        public PluginCategory Category { get; set; }
        
        /// <summary>
        /// 插件标签
        /// </summary>
        public List<string> Tags { get; set; } = new List<string>();
        
        /// <summary>
        /// 下载次数
        /// </summary>
        public int DownloadCount { get; set; }
        
        /// <summary>
        /// 评分（1-5）
        /// </summary>
        public double Rating { get; set; }
        
        /// <summary>
        /// 评分人数
        /// </summary>
        public int RatingCount { get; set; }
        
        /// <summary>
        /// 插件图标URL
        /// </summary>
        public string IconUrl { get; set; }
        
        /// <summary>
        /// 插件下载URL
        /// </summary>
        public string DownloadUrl { get; set; }
        
        /// <summary>
        /// 插件主页URL
        /// </summary>
        public string HomepageUrl { get; set; }
        
        /// <summary>
        /// 发布日期
        /// </summary>
        public DateTime PublishDate { get; set; }
        
        /// <summary>
        /// 最后更新日期
        /// </summary>
        public DateTime LastUpdateDate { get; set; }
        
        /// <summary>
        /// 支持的最低应用版本
        /// </summary>
        public string MinAppVersion { get; set; }
        
        /// <summary>
        /// 是否已安装
        /// </summary>
        public bool IsInstalled { get; set; }
        
        /// <summary>
        /// 是否需要更新
        /// </summary>
        public bool HasUpdate { get; set; }
        
        /// <summary>
        /// 本地安装路径
        /// </summary>
        public string LocalPath { get; set; }
        
        /// <summary>
        /// 安装日期
        /// </summary>
        public DateTime? InstallDate { get; set; }
        
        /// <summary>
        /// 插件大小（字节）
        /// </summary>
        public long Size { get; set; }
        
        /// <summary>
        /// 插件状态
        /// </summary>
        public PluginStatus Status { get; set; }
    }
    
    /// <summary>
    /// 插件类别
    /// </summary>
    public enum PluginCategory
    {
        /// <summary>
        /// 漏洞检测
        /// </summary>
        VulnerabilityDetection,
        
        /// <summary>
        /// 端口扫描
        /// </summary>
        PortScanning,
        
        /// <summary>
        /// 报告生成
        /// </summary>
        Reporting,
        
        /// <summary>
        /// 数据分析
        /// </summary>
        DataAnalysis,
        
        /// <summary>
        /// 界面扩展
        /// </summary>
        UIExtension,
        
        /// <summary>
        /// 集成工具
        /// </summary>
        Integration,
        
        /// <summary>
        /// 其他
        /// </summary>
        Other
    }
    
    /// <summary>
    /// 插件状态
    /// </summary>
    public enum PluginStatus
    {
        /// <summary>
        /// 可用
        /// </summary>
        Available,
        
        /// <summary>
        /// 已安装
        /// </summary>
        Installed,
        
        /// <summary>
        /// 有更新
        /// </summary>
        UpdateAvailable,
        
        /// <summary>
        /// 安装中
        /// </summary>
        Installing,
        
        /// <summary>
        /// 更新中
        /// </summary>
        Updating,
        
        /// <summary>
        /// 卸载中
        /// </summary>
        Uninstalling,
        
        /// <summary>
        /// 错误
        /// </summary>
        Error
    }
    
    /// <summary>
    /// 插件市场响应
    /// </summary>
    public class PluginMarketResponse
    {
        /// <summary>
        /// 插件列表
        /// </summary>
        public List<Plugin> Plugins { get; set; }
        
        /// <summary>
        /// 总数量
        /// </summary>
        public int TotalCount { get; set; }
        
        /// <summary>
        /// 当前页
        /// </summary>
        public int CurrentPage { get; set; }
        
        /// <summary>
        /// 总页数
        /// </summary>
        public int TotalPages { get; set; }
    }
    
    /// <summary>
    /// 插件搜索条件
    /// </summary>
    public class PluginSearchCriteria
    {
        /// <summary>
        /// 搜索关键词
        /// </summary>
        public string Keyword { get; set; }
        
        /// <summary>
        /// 类别筛选
        /// </summary>
        public PluginCategory? Category { get; set; }
        
        /// <summary>
        /// 排序方式
        /// </summary>
        public PluginSortOrder SortOrder { get; set; } = PluginSortOrder.Popularity;
        
        /// <summary>
        /// 页码
        /// </summary>
        public int Page { get; set; } = 1;
        
        /// <summary>
        /// 每页数量
        /// </summary>
        public int PageSize { get; set; } = 20;
    }
    
    /// <summary>
    /// 插件排序方式
    /// </summary>
    public enum PluginSortOrder
    {
        /// <summary>
        /// 人气（下载量）
        /// </summary>
        Popularity,
        
        /// <summary>
        /// 最新发布
        /// </summary>
        Newest,
        
        /// <summary>
        /// 最近更新
        /// </summary>
        RecentlyUpdated,
        
        /// <summary>
        /// 评分最高
        /// </summary>
        HighestRated,
        
        /// <summary>
        /// 名称排序
        /// </summary>
        Name
    }
}
