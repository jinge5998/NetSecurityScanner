using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 网络拓扑发现服务
    /// </summary>
    public class NetworkTopologyService
    {
        private readonly int _timeout;
        private readonly Dictionary<string, NetworkDevice> _discoveredDevices;

        public NetworkTopologyService(int timeout = 1000)
        {
            _timeout = timeout;
            _discoveredDevices = new Dictionary<string, NetworkDevice>();
        }

        /// <summary>
        /// 发现网络设备
        /// </summary>
        public async Task<List<NetworkDevice>> DiscoverNetworkAsync(string networkRange, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        {
            _discoveredDevices.Clear();
            var devices = new List<NetworkDevice>();

            // 解析网络范围
            var ipRange = ParseNetworkRange(networkRange);
            if (ipRange == null)
            {
                progress?.Report("无效的网络范围格式");
                return devices;
            }

            progress?.Report($"开始扫描网络: {networkRange}");

            // 并行扫描IP地址
            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(50); // 限制并发数

            foreach (var ip in ipRange)
            {
                await semaphore.WaitAsync(cancellationToken);
                
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var device = await ScanDeviceAsync(ip, cancellationToken);
                        if (device != null)
                        {
                            lock (_discoveredDevices)
                            {
                                _discoveredDevices[ip] = device;
                                devices.Add(device);
                            }
                            progress?.Report($"发现设备: {ip} - {device.Hostname}");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NetworkTopologyService] 扫描设备失败: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            
            progress?.Report($"扫描完成，共发现 {devices.Count} 个设备");
            
            // 分析设备关系
            AnalyzeDeviceRelationships(devices);
            
            return devices;
        }

        /// <summary>
        /// 扫描单个设备
        /// </summary>
        private async Task<NetworkDevice?> ScanDeviceAsync(string ip, CancellationToken cancellationToken)
        {
            try
            {
                // 首先Ping检测
                if (!await PingHostAsync(ip, cancellationToken))
                {
                    return null;
                }

                var device = new NetworkDevice
                {
                    IPAddress = ip,
                    Status = DeviceStatus.Online,
                    DiscoveryTime = DateTime.Now
                };

                // 获取主机名
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ip);
                    device.Hostname = hostEntry.HostName;
                }
                catch
                {
                    device.Hostname = ip;
                }

                // 获取MAC地址
                device.MacAddress = GetMacAddress(ip);

                // 端口扫描获取开放端口
                device.OpenPorts = await ScanCommonPortsAsync(ip, cancellationToken);

                // 设备指纹识别
                device.DeviceType = FingerprintDevice(device);

                // 获取设备信息
                await EnrichDeviceInfoAsync(device, cancellationToken);

                return device;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Ping主机
        /// </summary>
        private async Task<bool> PingHostAsync(string ip, CancellationToken cancellationToken)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, _timeout);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 扫描常用端口
        /// </summary>
        private async Task<List<int>> ScanCommonPortsAsync(string ip, CancellationToken cancellationToken)
        {
            var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443 };
            var openPorts = new List<int>();

            var tasks = commonPorts.Select(async port =>
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(ip, port);
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeoutCts.CancelAfter(_timeout);
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    await connectTask.WaitAsync(timeoutCts.Token);
                    lock (openPorts)
                    {
                        openPorts.Add(port);
                    }
                }
                catch (OperationCanceledException)
                {
                    // 忽略超时或取消异常
                }
                catch (Exception)
                {
                    // 忽略所有其他异常
                }
            });

            await Task.WhenAll(tasks);
            return openPorts.OrderBy(p => p).ToList();
        }

        /// <summary>
        /// 获取MAC地址
        /// </summary>
        private string? GetMacAddress(string ip)
        {
            try
            {
                // 使用ARP获取MAC地址
                var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = $"-a {ip}",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // 解析MAC地址
                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains(ip))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            var mac = parts[1].Trim();
                            if (mac.Contains("-") || mac.Contains(":"))
                            {
                                return mac;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetworkTopologyService] 获取MAC地址失败: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// 设备指纹识别
        /// </summary>
        private DeviceType FingerprintDevice(NetworkDevice device)
        {
            var ports = device.OpenPorts;

            // 根据开放端口判断设备类型
            if (ports.Contains(445) || ports.Contains(139))
                return DeviceType.Windows;
            
            if (ports.Contains(22) && ports.Contains(80))
                return DeviceType.Linux;
            
            if (ports.Contains(80) || ports.Contains(8080) || ports.Contains(443))
                return DeviceType.WebServer;
            
            if (ports.Contains(3306))
                return DeviceType.Database;
            
            if (ports.Contains(53))
                return DeviceType.DNS;
            
            if (ports.Contains(25) || ports.Contains(110) || ports.Contains(143))
                return DeviceType.MailServer;
            
            if (ports.Contains(3389))
                return DeviceType.Windows;
            
            if (ports.Contains(5900))
                return DeviceType.VNC;
            
            return DeviceType.Unknown;
        }

        /// <summary>
        /// 丰富设备信息
        /// </summary>
        private async Task EnrichDeviceInfoAsync(NetworkDevice device, CancellationToken cancellationToken)
        {
            // 尝试获取HTTP服务信息
            if (device.OpenPorts.Contains(80))
            {
                try
                {
                    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                    var response = await client.GetAsync($"http://{device.IPAddress}", cancellationToken);
                    
                    if (response.Headers.Contains("Server"))
                    {
                        device.ServiceInfo = string.Join(", ", response.Headers.GetValues("Server"));
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NetworkTopologyService] 获取HTTP服务信息失败: {ex.Message}");
                }
            }

            // 尝试获取HTTPS服务信息
            if (device.OpenPorts.Contains(443))
            {
                try
                {
                    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                    var response = await client.GetAsync($"https://{device.IPAddress}", cancellationToken);
                    
                    if (string.IsNullOrEmpty(device.ServiceInfo) && response.Headers.Contains("Server"))
                    {
                        device.ServiceInfo = string.Join(", ", response.Headers.GetValues("Server"));
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NetworkTopologyService] 获取HTTPS服务信息失败: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// 分析设备关系
        /// </summary>
        private void AnalyzeDeviceRelationships(List<NetworkDevice> devices)
        {
            foreach (var device in devices)
            {
                // 根据子网分析可能的网关关系
                var ipParts = device.IPAddress.Split('.');
                if (ipParts.Length == 4)
                {
                    var subnet = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}";
                    device.Subnet = subnet;
                    
                    // 假设.1是网关
                    var gatewayIp = $"{subnet}.1";
                    if (devices.Any(d => d.IPAddress == gatewayIp))
                    {
                        device.Gateway = gatewayIp;
                    }
                }

                // 根据开放端口推断服务依赖关系
                device.Dependencies = InferDependencies(device, devices);
            }
        }

        /// <summary>
        /// 推断设备依赖关系
        /// </summary>
        private List<string> InferDependencies(NetworkDevice device, List<NetworkDevice> allDevices)
        {
            var dependencies = new List<string>();

            // 如果设备使用DNS，可能依赖DNS服务器
            if (device.OpenPorts.Contains(53) == false) // 不是DNS服务器
            {
                var dnsServers = allDevices.Where(d => d.OpenPorts.Contains(53)).Select(d => d.IPAddress);
                dependencies.AddRange(dnsServers);
            }

            // Web服务器可能依赖数据库
            if (device.DeviceType == DeviceType.WebServer)
            {
                var databases = allDevices.Where(d => d.DeviceType == DeviceType.Database).Select(d => d.IPAddress);
                dependencies.AddRange(databases);
            }

            return dependencies.Distinct().ToList();
        }

        /// <summary>
        /// 解析网络范围
        /// </summary>
        private List<string>? ParseNetworkRange(string range)
        {
            var ips = new List<string>();

            try
            {
                // CIDR格式: 192.168.1.0/24
                if (range.Contains("/"))
                {
                    var parts = range.Split('/');
                    if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var baseIp))
                    {
                        var prefix = int.Parse(parts[1]);
                        if (prefix >= 16 && prefix <= 30) // 限制范围大小
                        {
                            ips = GenerateIpRange(baseIp, prefix);
                        }
                    }
                }
                // 范围格式: 192.168.1.1-192.168.1.254
                else if (range.Contains("-"))
                {
                    var parts = range.Split('-');
                    if (parts.Length == 2)
                    {
                        ips = GenerateIpRange(parts[0].Trim(), parts[1].Trim());
                    }
                }
                // 单IP
                else if (IPAddress.TryParse(range, out _))
                {
                    ips.Add(range);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NetworkTopologyService] 解析IP范围失败: {ex.Message}");
            }

            return ips.Count > 0 ? ips : null;
        }

        /// <summary>
        /// 根据CIDR生成IP范围
        /// </summary>
        private List<string> GenerateIpRange(IPAddress baseIp, int prefix)
        {
            var ips = new List<string>();
            var bytes = baseIp.GetAddressBytes();
            var ipInt = BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
            
            var hostBits = 32 - prefix;
            var numHosts = (int)Math.Pow(2, hostBits) - 2;
            var networkAddress = (uint)(ipInt & ~(numHosts + 1));

            for (int i = 1; i <= numHosts && i < 256; i++) // 限制最多254个
            {
                var hostIp = networkAddress + (uint)i;
                var hostBytes = BitConverter.GetBytes(hostIp).Reverse().ToArray();
                ips.Add(new IPAddress(hostBytes).ToString());
            }

            return ips;
        }

        /// <summary>
        /// 生成IP范围
        /// </summary>
        private List<string> GenerateIpRange(string startIp, string endIp)
        {
            var ips = new List<string>();
            
            if (!IPAddress.TryParse(startIp, out var start) || !IPAddress.TryParse(endIp, out var end))
                return ips;

            var startBytes = start.GetAddressBytes();
            var endBytes = end.GetAddressBytes();

            // 简化的实现：只支持最后一段变化
            if (startBytes[0] == endBytes[0] && startBytes[1] == endBytes[1] && startBytes[2] == endBytes[2])
            {
                for (int i = startBytes[3]; i <= endBytes[3] && i <= 254; i++)
                {
                    ips.Add($"{startBytes[0]}.{startBytes[1]}.{startBytes[2]}.{i}");
                }
            }

            return ips;
        }

        /// <summary>
        /// 获取网络统计信息
        /// </summary>
        public NetworkStatistics GetNetworkStatistics(List<NetworkDevice> devices)
        {
            return new NetworkStatistics
            {
                TotalDevices = devices.Count,
                OnlineDevices = devices.Count(d => d.Status == DeviceStatus.Online),
                OfflineDevices = devices.Count(d => d.Status == DeviceStatus.Offline),
                DeviceTypeDistribution = devices.GroupBy(d => d.DeviceType)
                    .ToDictionary(g => g.Key, g => g.Count()),
                TotalOpenPorts = devices.Sum(d => d.OpenPorts.Count),
                SubnetDistribution = devices.GroupBy(d => d.Subnet)
                    .ToDictionary(g => g.Key ?? "Unknown", g => g.Count())
            };
        }
    }

    /// <summary>
    /// 网络设备
    /// </summary>
    public class NetworkDevice
    {
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string? MacAddress { get; set; }
        public DeviceType DeviceType { get; set; }
        public DeviceStatus Status { get; set; }
        public List<int> OpenPorts { get; set; } = new();
        public string? ServiceInfo { get; set; }
        public string? OperatingSystem { get; set; }
        public string? Subnet { get; set; }
        public string? Gateway { get; set; }
        public List<string> Dependencies { get; set; } = new();
        public DateTime DiscoveryTime { get; set; }
        public DateTime LastSeen { get; set; }
    }

    /// <summary>
    /// 设备类型
    /// </summary>
    public enum DeviceType
    {
        Unknown,
        Windows,
        Linux,
        Router,
        Switch,
        Firewall,
        WebServer,
        Database,
        DNS,
        MailServer,
        Printer,
        Camera,
        VNC,
        Other
    }

    /// <summary>
    /// 设备状态
    /// </summary>
    public enum DeviceStatus
    {
        Unknown,
        Online,
        Offline,
        Unreachable
    }

    /// <summary>
    /// 网络统计
    /// </summary>
    public class NetworkStatistics
    {
        public int TotalDevices { get; set; }
        public int OnlineDevices { get; set; }
        public int OfflineDevices { get; set; }
        public Dictionary<DeviceType, int> DeviceTypeDistribution { get; set; } = new();
        public int TotalOpenPorts { get; set; }
        public Dictionary<string, int> SubnetDistribution { get; set; } = new();
    }
}
