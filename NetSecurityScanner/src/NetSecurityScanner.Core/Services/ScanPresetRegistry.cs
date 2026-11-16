using System;
using System.Collections.Generic;
using System.Linq;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services;

/// <summary>
/// 综合扫描预设注册表（v1.0.1.3 引入，6 个内置预设 + 统一端口字符串解析）。
/// 替代 MainWindow 中旧版 ParsePortRange 方法。
/// </summary>
public static class ScanPresetRegistry
{
    /// <summary>Top-100 常用端口（Quick 预设）</summary>
    public static readonly IReadOnlyList<int> QuickPorts = new List<int>
    {
        7, 20, 21, 22, 23, 25, 26, 37, 43, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85,
        88, 89, 90, 99, 100, 106, 110, 111, 113, 119, 123, 125, 135, 137, 138, 139, 143, 144,
        161, 162, 163, 164, 174, 177, 178, 179, 191, 194, 199, 201, 202, 204, 206, 209,
        210, 213, 220, 245, 347, 363, 369, 370, 372, 389, 427, 433, 434, 443, 444, 445,
        450, 451, 464, 468, 497, 500, 502, 512, 513, 514, 515, 520, 521, 540, 548, 554,
        555, 563, 587, 631, 636, 873, 902, 989, 990, 993, 995, 998, 999,
        1000, 1024, 1025, 1026, 1027, 1028, 1029, 1058, 1059, 1080, 1099, 1100, 1110,
        1234, 1433, 1521, 1723, 1812, 1883, 1900, 2000, 2049, 2082, 2083, 2086, 2087,
        2095, 2096, 2222, 2375, 2376, 3000, 3001, 3306, 3389, 3690, 4000, 4443, 4444,
        5000, 5001, 5060, 5222, 5432, 5555, 5672, 5900, 5984, 5985, 5986, 6379, 6443,
        6660, 6661, 6667, 7000, 7001, 7077, 7474, 7680, 8000, 8001, 8008, 8009, 8010,
        8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8443,
        8500, 8530, 8531, 8883, 8888, 9000, 9001, 9042, 9090, 9091, 9100, 9200, 9300,
        9418, 9999, 10000, 10080, 11211, 15672, 15692, 26379, 27017, 27018, 27019, 28017, 50000
    }.Distinct().OrderBy(p => p).ToList();

    /// <summary>1-1000 端口（Standard 预设）</summary>
    public static readonly IReadOnlyList<int> StandardPorts =
        Enumerable.Range(1, 1000).ToList();

    /// <summary>1-65535 全端口（Deep 预设）</summary>
    public static readonly IReadOnlyList<int> DeepPorts =
        Enumerable.Range(1, 65535).ToList();

    /// <summary>Web 服务常用端口（Web 预设）</summary>
    public static readonly IReadOnlyList<int> WebPorts = new List<int>
    {
        80, 443, 1080, 1180, 1280, 1443, 1518, 1741, 1801, 1935,
        1984, 2000, 2030, 2082, 2083, 2086, 2087, 2095, 2096, 2186,
        2375, 2376, 2380, 2404, 2424, 2443, 2480, 2500, 2600, 2612,
        2710, 2812, 2944, 3000, 3001, 3052, 3074, 3128, 3225, 3325,
        3333, 3425, 3478, 3493, 3500, 3527, 3600, 3645, 3690, 3702,
        3724, 3784, 3826, 3827, 3828, 3856, 3880, 3914, 3935, 3990,
        4000, 4036, 4111, 4118, 4125, 4126, 4129, 4242, 4321, 4443,
        4500, 4567, 4711, 4712, 4713, 4714, 4724, 4842, 4848, 4877,
        4894, 4899, 4949, 4999, 5000, 5001, 5002, 5003, 5009, 5010,
        5050, 5060, 5061, 5093, 5099, 5100, 5190, 5222, 5223, 5225,
        5226, 5269, 5280, 5298, 5353, 5432, 5500, 5510, 5520, 5530,
        5540, 5550, 5555, 5560, 5566, 5631, 5632, 5666, 5672, 5678,
        5683, 5800, 5801, 5802, 5803, 5900, 5901, 5902, 5903, 5950,
        5984, 5985, 5986, 6000, 6001, 6005, 6379, 6443, 6660, 6661,
        6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6679, 6697,
        7000, 7001, 7002, 7004, 7005, 7007, 7019, 7025, 7070, 7100,
        7200, 7402, 7443, 7474, 7547, 7548, 7549, 7654, 7680, 7777,
        7778, 7780, 7787, 7788, 7799, 7900, 7901, 7902, 7903, 7911,
        8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
        8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019,
        8020, 8021, 8022, 8025, 8026, 8027, 8030, 8040, 8042, 8080,
        8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
        8091, 8101, 8118, 8123, 8161, 8181, 8200, 8222, 8243, 8280,
        8281, 8333, 8442, 8443, 8500, 8530, 8531, 8649, 8765, 8786,
        8800, 8843, 8873, 8880, 8883, 8888, 8899, 8900, 8901, 8909,
        8910, 8911, 8983, 8990, 8991, 9000, 9001, 9002, 9003, 9009,
        9010, 9011, 9020, 9025, 9030, 9040, 9042, 9080, 9090, 9091,
        9100, 9152, 9160, 9191, 9200, 9300, 9390, 9418, 9443, 9495,
        9500, 9535, 9595, 9616, 9626, 9656, 9667, 9669, 9745, 9876,
        9898, 9900, 9911, 9942, 9943, 9944, 9968, 9978, 9988, 9999,
        10000, 10080, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
        10629, 11000, 11110, 11211, 11371, 11967, 12000, 12174, 12345, 12546,
        12865, 13456, 13720, 13782, 13783, 14000, 14441, 14442, 15000, 15002,
        15003, 15004, 15660, 16000, 16001, 16016, 16080, 16113, 16992, 16993,
        17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780,
        19801, 19842, 20000, 20005, 20031, 20221, 20828, 21571, 22939, 23523,
        24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356,
        50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 51413,
        52673, 52822, 52823, 52824, 56000, 60000, 60010, 60100, 61532, 61900
    }.Distinct().OrderBy(p => p).ToList();

    /// <summary>数据库服务常用端口（Database 预设）</summary>
    public static readonly IReadOnlyList<int> DatabasePorts = new List<int>
    {
        1433, 1434, 1521, 1830, 3306, 3307, 3351, 5432, 5433, 5500,
        5544, 5550, 6379, 6380, 7000, 7001, 7474, 7475, 8529, 8530,
        8531, 9042, 9092, 9160, 9200, 9201, 9300, 9301, 9418, 11211,
        15672, 15692, 16379, 26379, 27017, 27018, 27019, 28017, 50000
    }.Distinct().OrderBy(p => p).ToList();

    /// <summary>根据预设返回端口列表（Custom 需结合 options.CustomPorts 解析）</summary>
    public static IReadOnlyList<int> GetPorts(ScanPreset preset, string customPorts = "")
    {
        return preset switch
        {
            ScanPreset.Quick => QuickPorts,
            ScanPreset.Standard => StandardPorts,
            ScanPreset.Deep => DeepPorts,
            ScanPreset.Web => WebPorts,
            ScanPreset.Database => DatabasePorts,
            ScanPreset.Custom => ParsePortList(customPorts),
            _ => StandardPorts
        };
    }

    /// <summary>把端口列表字符串解析为去重排序的 int 列表
    /// <para>支持混合格式：</para>
    /// <list type="bullet">
    ///   <item>范围："1-1000"</item>
    ///   <item>列表："22,80,443"</item>
    ///   <item>混合："1-100,443,8080-8090"</item>
    /// </list>
    /// </summary>
    /// <exception cref="ArgumentException">端口格式非法 / 越界 / 范围倒序时抛出</exception>
    public static List<int> ParsePortList(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("端口范围不能为空", nameof(input));

        var result = new SortedSet<int>();
        var parts = input.Split(',', StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (trimmed.Length == 0) continue;

            if (trimmed.Contains('-'))
            {
                var rangeParts = trimmed.Split('-', StringSplitOptions.RemoveEmptyEntries);
                if (rangeParts.Length != 2)
                    throw new ArgumentException($"端口范围格式错误: '{trimmed}'", nameof(input));

                if (!int.TryParse(rangeParts[0].Trim(), out int start) || !int.TryParse(rangeParts[1].Trim(), out int end))
                    throw new ArgumentException($"端口范围数字无效: '{trimmed}'", nameof(input));

                if (start < 1 || end > 65535 || start > end)
                    throw new ArgumentException($"端口范围越界或倒序: '{trimmed}' (1 ≤ start ≤ end ≤ 65535)", nameof(input));

                for (int p = start; p <= end; p++) result.Add(p);
            }
            else
            {
                if (!int.TryParse(trimmed, out int port))
                    throw new ArgumentException($"端口号无效: '{trimmed}'", nameof(input));

                if (port < 1 || port > 65535)
                    throw new ArgumentException($"端口号越界: {port} (1-65535)", nameof(input));

                result.Add(port);
            }
        }

        return result.ToList();
    }

    /// <summary>预览耗时估算（粗略公式：端口数 × 超时 / 并发，取上限 1 秒）</summary>
    public static TimeSpan EstimateDuration(int portCount, int concurrency, int timeoutSeconds)
    {
        if (portCount <= 0 || concurrency <= 0) return TimeSpan.Zero;
        var seconds = (double)portCount * timeoutSeconds / Math.Max(1, concurrency);
        return TimeSpan.FromSeconds(Math.Max(1, seconds));
    }
}
