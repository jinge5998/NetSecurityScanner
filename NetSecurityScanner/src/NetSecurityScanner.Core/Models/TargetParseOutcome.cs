using System.Collections.Generic;

namespace NetSecurityScanner.Core.Models
{
    /// <summary>
    /// 目标校验结果。Error 非空表示整体拒绝（此时其余字段无意义）。
    /// </summary>
    public class TargetParseOutcome
    {
        public List<string> Targets { get; init; } = new();
        public int Total { get; init; }
        public int Deduped { get; init; }
        public int Invalid { get; init; }
        public string? Error { get; init; }
    }
}
