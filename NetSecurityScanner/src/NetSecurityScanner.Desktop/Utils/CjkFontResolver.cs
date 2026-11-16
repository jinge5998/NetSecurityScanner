using System;
using System.Linq;
using SkiaSharp;

namespace NetSecurityScanner.Utils
{
    /// <summary>
    /// 系统中文字体解析器。
    /// LiveChartsCore 通过 SkiaSharp 渲染文本，WPF 的 FontFamily 不会被自动继承。
    /// 因此在应用启动阶段需要为所有图表统一指定一个含中文字形的 SKTypeface。
    ///
    /// 解析策略（按顺序）：
    ///   1. 候选字体名按从优到次优逐个尝试 SKTypeface.FromFamilyName，
    ///      只要返回非空且族名非空即视为命中（因为 SKTypeface.Default 也是非空）。
    ///   2. 全部候选失败时回退到 SKFontManager.Default.MatchCharacter('汉')，
    ///      主动寻找系统中能渲染汉字的字体。
    ///   3. 最终兜底为 SKTypeface.Default。
    /// </summary>
    public static class CjkFontResolver
    {
        /// <summary>
        /// 系统中文字体候选（按从优到次优排序）。
        /// Windows 通常含 Microsoft YaHei UI / Microsoft YaHei / SimHei 之一；
        /// macOS 通常含 PingFang SC；Linux 容器可能含 Noto Sans CJK SC。
        /// </summary>
        private static readonly string[] Candidates = new[]
        {
            "Microsoft YaHei UI",
            "Microsoft YaHei",
            "SimHei",
            "SimSun",
            "Noto Sans CJK SC",
            "Noto Sans SC",
            "Source Han Sans SC",
            "Source Han Sans CN",
            "PingFang SC",
            "Hiragino Sans GB",
            "Segoe UI"
        };

        /// <summary>
        /// 当前进程解析到的中文字体。该字段在首次访问时初始化，整个进程复用。
        /// </summary>
        public static SKTypeface Resolved { get; } = Resolve();

        /// <summary>
        /// 解析系统可用的中文字体。
        /// </summary>
        private static SKTypeface Resolve()
        {
            try
            {
                foreach (var name in Candidates)
                {
                    try
                    {
                        var tf = SKTypeface.FromFamilyName(name);
                        // 注意：SKTypeface.Default.FamilyName 也可能为 "Microsoft Sans Serif" 之类，
                        // 所以这里用 SKFontManager.MatchFamily 来二次确认族名确实存在。
                        if (tf != null && !string.IsNullOrEmpty(tf.FamilyName))
                        {
                            var match = SKFontManager.Default.MatchFamily(name);
                            if (match != null)
                            {
                                System.Diagnostics.Debug.WriteLine(
                                    $"[CjkFontResolver] Resolved CJK font via MatchFamily: {match.FamilyName} (Handle={match.Handle}); FromFamilyName fallback: {tf.FamilyName} (Handle={tf.Handle})");
                                return match;
                            }
                        }
                    }
                    catch
                    {
                        // 忽略单次失败，尝试下一个候选
                    }
                }

                // 全部 FromFamilyName 失败 → 主动匹配一个能渲染汉字的字体
                try
                {
                    var matched = SKFontManager.Default.MatchCharacter('汉');
                    if (matched != null)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"[CjkFontResolver] Resolved CJK font via MatchCharacter: {matched.FamilyName} (Handle={matched.Handle})");
                        return matched;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[CjkFontResolver] MatchCharacter failed: {ex.Message}");
                }

                System.Diagnostics.Debug.WriteLine("[CjkFontResolver] Falling back to SKTypeface.Default");
                return SKTypeface.Default;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CjkFontResolver] Unexpected error: {ex.Message}");
                return SKTypeface.Default;
            }
        }

        /// <summary>
        /// 返回当前选中的中文字体族名（用于调试日志输出）。
        /// </summary>
        public static string ResolvedFamilyName => Resolved?.FamilyName ?? "(null)";
    }
}
