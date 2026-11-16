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
        public static List<string> ParseTargets(string input, TargetType type)
        {
            return type switch
            {
                TargetType.Single => new List<string> { input.Trim() },
                TargetType.Range => ParseIpRange(input),
                TargetType.CIDR => ParseCidr(input),
                TargetType.ListFile => ParseFromFile(input),
                _ => throw new NotSupportedException()
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

            var targets = new List<string>();
            var current = startBytes.ToArray();

            while (true)
            {
                targets.Add(new IPAddress(current).ToString());

                for (int i = 3; i >= 0; i--)
                {
                    if (++current[i] <= 255) break;
                    current[i] = 0;
                }

                if (current.SequenceEqual(endBytes)) break;
            }

            targets.Add(endIp.ToString());
            return targets;
        }

        private static List<string> ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            var ip = IPAddress.Parse(parts[0]);
            var prefix = int.Parse(parts[1]);

            var ipBytes = ip.GetAddressBytes();
            var mask = 0xFFFFFFFF << (32 - prefix);

            var network = BitConverter.ToUInt32(ipBytes.Reverse().ToArray(), 0) & mask;
            var broadcast = network | (uint)(~mask);

            var targets = new List<string>();

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
