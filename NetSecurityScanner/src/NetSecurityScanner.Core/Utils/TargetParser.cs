using NetSecurityScanner.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace NetSecurityScanner.Utils
{
    public static class TargetParser
    {
        /// <summary>
        /// 解析目标时生成的最大IP数量限制（防止内存爆炸）
        /// </summary>
        public const int MaxTargetsLimit = 65536;

        public static List<string> ParseTargets(string input, TargetType type)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            var trimmed = input.Trim();
            if (string.IsNullOrEmpty(trimmed))
                throw new ArgumentException("目标输入不能为空", nameof(input));

            return type switch
            {
                TargetType.Single => new List<string> { trimmed },
                TargetType.Range => ParseIpRange(trimmed),
                TargetType.CIDR => ParseCidr(trimmed),
                TargetType.ListFile => ParseFromFile(trimmed),
                _ => throw new NotSupportedException($"不支持的目标类型: {type}")
            };
        }

        private static List<string> ParseIpRange(string range)
        {
            var parts = range.Split('-');
            if (parts.Length != 2) throw new ArgumentException("无效的IP段格式，正确格式: 192.168.1.1-192.168.1.254");

            var startIp = IPAddress.Parse(parts[0].Trim());
            var endIp = IPAddress.Parse(parts[1].Trim());

            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();

            // 计算IP数量，如果超过限制则抛出异常
            long startLong = (long)startBytes[0] << 24 | (long)startBytes[1] << 16 | (long)startBytes[2] << 8 | startBytes[3];
            long endLong = (long)endBytes[0] << 24 | (long)endBytes[1] << 16 | (long)endBytes[2] << 8 | endBytes[3];

            // 如果 start > end，交换（用户填入反向范围）
            if (startLong > endLong)
            {
                (startIp, endIp) = (endIp, startIp);
                (startBytes, endBytes) = (endBytes, startBytes);
                (startLong, endLong) = (endLong, startLong);
            }

            long ipCount = endLong - startLong + 1;
            if (ipCount > MaxTargetsLimit)
            {
                throw new ArgumentException(
                    $"IP范围包含 {ipCount} 个地址，超过最大限制 {MaxTargetsLimit}。请缩小范围。");
            }

            var targets = new List<string>();
            var current = startBytes.ToArray();

            while (true)
            {
                targets.Add(new IPAddress(current).ToString());

                // 如果当前IP已经是结束IP，停止（处理 start==end 的情况）
                if (current.SequenceEqual(endBytes)) break;

                for (int i = 3; i >= 0; i--)
                {
                    if (++current[i] <= 255) break;
                    current[i] = 0;
                }
            }

            return targets;
        }

        private static List<string> ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2)
                throw new ArgumentException("CIDR格式无效，应为: IP/前缀长度");

            var ip = IPAddress.Parse(parts[0]);
            if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32)
                throw new ArgumentException("CIDR前缀长度必须在 0-32 之间");

            // 安全限制：/0（整个IPv4空间）或/1（~2^31个地址）不可行
            if (prefix < 8)
            {
                throw new ArgumentException(
                    $"CIDR前缀 /{prefix} 会生成超过 {MaxTargetsLimit} 个目标，已被限制。最大允许前缀为 /8（约16M地址）。");
            }

            var ipBytes = ip.GetAddressBytes();
            var mask = 0xFFFFFFFF << (32 - prefix);

            var network = BitConverter.ToUInt32(ipBytes.Reverse().ToArray(), 0) & mask;
            var broadcast = network | (uint)(~mask);

            // 计算目标数量，如果超过限制则截断
            long hostCount = (1L << (32 - prefix)) - 2; // 减掉网络地址和广播地址
            if (hostCount > MaxTargetsLimit)
            {
                throw new ArgumentException(
                    $"CIDR /{prefix} 会生成 {hostCount} 个目标，超过最大限制 {MaxTargetsLimit}。");
            }

            var targets = new List<string>();

            // 特殊处理 /32：返回单个地址（主机路由）
            if (prefix == 32)
            {
                targets.Add(ip.ToString());
                return targets;
            }

            // 特殊处理 /31：点到点链路，无可用主机地址（RFC 3021）
            if (prefix == 31)
            {
                return targets;
            }

            for (uint i = network + 1; i < broadcast; i++)
            {
                var bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                targets.Add(new IPAddress(bytes).ToString());
            }

            return targets;
        }

        private static List<string> ParseFromFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("目标列表文件不存在");

            return File.ReadAllLines(filePath)
                .Where(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                .Select(line => line.Trim())
                .Distinct()
                .ToList();
        }

        public static bool ValidateTarget(string target, TargetType type)
        {
            try
            {
                ParseTargets(target, type);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}