using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core
{
  public class CameraDiscoveryService : IDisposable
  {
    private readonly List<UdpClient> _udpClients = new();
    private bool _disposed;

    public event Action<DiscoveredCamera>? CameraDiscovered;

    public async Task<List<DiscoveredCamera>> DiscoverAsync(
        int timeoutMs = 10000,
        CancellationToken ct = default)
    {
      var discovered = new List<DiscoveredCamera>();
      var discoveredIps = new HashSet<string>();

      void OnCameraDiscovered(DiscoveredCamera camera)
      {
        lock (discovered)
        {
          if (discoveredIps.Add(camera.Ip))
          {
            discovered.Add(camera);
            CameraDiscovered?.Invoke(camera);
          }
        }
      }

      var tasks = new List<Task>
      {
        DiscoverUpnpAsync(OnCameraDiscovered, timeoutMs, ct),
        DiscoverMdnsAsync(OnCameraDiscovered, timeoutMs, ct),
        DiscoverWsDiscoveryAsync(OnCameraDiscovered, timeoutMs, ct),
        DiscoverOnvifProbeAsync(OnCameraDiscovered, timeoutMs, ct)
      };

      await Task.WhenAll(tasks);

      return discovered;
    }

    private async Task DiscoverUpnpAsync(
        Action<DiscoveredCamera> onDiscovered, int timeoutMs, CancellationToken ct)
    {
      try
      {
        using var udpClient = new UdpClient();
        udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udpClient.Client.ReceiveTimeout = 2000;
        udpClient.Client.SendTimeout = 2000;

        var searchMessage = "M-SEARCH * HTTP/1.1\r\n" +
                            "HOST: 239.255.255.250:1900\r\n" +
                            "MAN: \"ssdp:discover\"\r\n" +
                            "MX: 3\r\n" +
                            "ST: upnp:rootdevice\r\n" +
                            "ST: urn:schemas-upnp-org:device:NetworkCamera:1\r\n" +
                            "ST: urn:schemas-upnp-org:device:DigitalSecurityCamera:1\r\n" +
                            "\r\n";

        var searchBytes = Encoding.ASCII.GetBytes(searchMessage);
        var multicastEp = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);

        await udpClient.SendAsync(searchBytes, searchBytes.Length, multicastEp);

        var deadline = DateTime.Now.AddMilliseconds(timeoutMs);
        while (DateTime.Now < deadline && !ct.IsCancellationRequested)
        {
          try
          {
            var result = await udpClient.ReceiveAsync();
            var response = Encoding.ASCII.GetString(result.Buffer);
            var ip = result.RemoteEndPoint.Address.ToString();

            if (IsCameraRelated(response))
            {
              var camera = ParseUpnpResponse(ip, response);
              if (camera != null)
                onDiscovered(camera);
            }
          }
          catch (SocketException)
          {
            break;
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"UPnP发现失败: {ex.Message}");
      }
    }

    private async Task DiscoverMdnsAsync(
        Action<DiscoveredCamera> onDiscovered, int timeoutMs, CancellationToken ct)
    {
      try
      {
        using var udpClient = new UdpClient();
        udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udpClient.Client.ReceiveTimeout = 2000;
        udpClient.Client.SendTimeout = 2000;

        var multicastEp = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
        udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 5353));

        var services = new[]
        {
          "_http._tcp.local",
          "_https._tcp.local",
          "_rtsp._tcp.local",
          "_onvif._tcp.local",
          "_axis-video._tcp.local",
          "_hikvision-http._tcp.local",
          "_dahua-http._tcp.local"
        };

        foreach (var service in services)
        {
          if (ct.IsCancellationRequested) break;
          try
          {
            var query = BuildMdnsQuery(service);
            await udpClient.SendAsync(query, query.Length, multicastEp);
          }
          catch { }
        }

        var deadline = DateTime.Now.AddMilliseconds(timeoutMs);
        while (DateTime.Now < deadline && !ct.IsCancellationRequested)
        {
          try
          {
            var result = await udpClient.ReceiveAsync();
            var response = result.Buffer;
            var ip = result.RemoteEndPoint.Address.ToString();

            var camera = ParseMdnsResponse(ip, response);
            if (camera != null)
              onDiscovered(camera);
          }
          catch (SocketException)
          {
            break;
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"mDNS发现失败: {ex.Message}");
      }
    }

    private async Task DiscoverWsDiscoveryAsync(
        Action<DiscoveredCamera> onDiscovered, int timeoutMs, CancellationToken ct)
    {
      try
      {
        using var udpClient = new UdpClient();
        udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udpClient.Client.ReceiveTimeout = 3000;
        udpClient.Client.SendTimeout = 2000;

        var probeMessage = BuildWsDiscoveryProbe();
        var multicastEp = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 3702);

        await udpClient.SendAsync(probeMessage, probeMessage.Length, multicastEp);

        var deadline = DateTime.Now.AddMilliseconds(timeoutMs);
        while (DateTime.Now < deadline && !ct.IsCancellationRequested)
        {
          try
          {
            var result = await udpClient.ReceiveAsync();
            var response = Encoding.UTF8.GetString(result.Buffer);
            var ip = result.RemoteEndPoint.Address.ToString();

            var camera = ParseWsDiscoveryResponse(ip, response);
            if (camera != null)
              onDiscovered(camera);
          }
          catch (SocketException)
          {
            break;
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"WS-Discovery失败: {ex.Message}");
      }
    }

    private async Task DiscoverOnvifProbeAsync(
        Action<DiscoveredCamera> onDiscovered, int timeoutMs, CancellationToken ct)
    {
      try
      {
        using var udpClient = new UdpClient();
        udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udpClient.Client.ReceiveTimeout = 3000;
        udpClient.Client.SendTimeout = 2000;

        var probeMessage = BuildOnvifProbeMessage();
        var multicastEp = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 3702);

        await udpClient.SendAsync(probeMessage, probeMessage.Length, multicastEp);

        var deadline = DateTime.Now.AddMilliseconds(timeoutMs);
        while (DateTime.Now < deadline && !ct.IsCancellationRequested)
        {
          try
          {
            var result = await udpClient.ReceiveAsync();
            var response = Encoding.UTF8.GetString(result.Buffer);
            var ip = result.RemoteEndPoint.Address.ToString();

            var camera = ParseOnvifProbeResponse(ip, response);
            if (camera != null)
              onDiscovered(camera);
          }
          catch (SocketException)
          {
            break;
          }
        }
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"ONVIF Probe失败: {ex.Message}");
      }
    }

    private static bool IsCameraRelated(string response)
    {
      return response.Contains("NetworkCamera", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("DigitalSecurityCamera", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("Camera", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("IPC", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("NVR", StringComparison.OrdinalIgnoreCase) ||
             response.Contains("DVR", StringComparison.OrdinalIgnoreCase);
    }

    private static DiscoveredCamera? ParseUpnpResponse(string ip, string response)
    {
      try
      {
        var camera = new DiscoveredCamera
        {
          Ip = ip,
          DiscoveryMethod = "UPnP/SSDP"
        };

        foreach (var line in response.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
          if (line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase))
          {
            camera.LocationUrl = line.Substring(9).Trim();
            ExtractPortFromUrl(camera.LocationUrl, camera);
          }
          else if (line.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase))
          {
            camera.Server = line.Substring(7).Trim();
            ExtractVendorFromServer(camera.Server, camera);
          }
          else if (line.StartsWith("USN:", StringComparison.OrdinalIgnoreCase))
          {
            camera.Usn = line.Substring(4).Trim();
          }
          else if (line.StartsWith("ST:", StringComparison.OrdinalIgnoreCase))
          {
            camera.ServiceType = line.Substring(3).Trim();
          }
        }

        return camera;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"UPnP解析失败: {ex.Message}");
        return null;
      }
    }

    private static DiscoveredCamera? ParseMdnsResponse(string ip, byte[] response)
    {
      try
      {
        var responseStr = Encoding.ASCII.GetString(response);
        if (!responseStr.Contains("camera", StringComparison.OrdinalIgnoreCase) &&
            !responseStr.Contains("onvif", StringComparison.OrdinalIgnoreCase) &&
            !responseStr.Contains("rtsp", StringComparison.OrdinalIgnoreCase) &&
            !responseStr.Contains("axis", StringComparison.OrdinalIgnoreCase) &&
            !responseStr.Contains("hikvision", StringComparison.OrdinalIgnoreCase) &&
            !responseStr.Contains("dahua", StringComparison.OrdinalIgnoreCase))
          return null;

        return new DiscoveredCamera
        {
          Ip = ip,
          DiscoveryMethod = "mDNS"
        };
      }
      catch
      {
        return null;
      }
    }

    private static DiscoveredCamera? ParseWsDiscoveryResponse(string ip, string response)
    {
      try
      {
        if (!response.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase) &&
            !response.Contains("Device", StringComparison.OrdinalIgnoreCase))
          return null;

        var camera = new DiscoveredCamera
        {
          Ip = ip,
          DiscoveryMethod = "WS-Discovery"
        };

        var xAddrsMatch = System.Text.RegularExpressions.Regex.Match(
            response, "<d:XAddrs>(.*?)</d:XAddrs>", System.Text.RegularExpressions.RegexOptions.Singleline);
        if (xAddrsMatch.Success)
        {
          camera.XAddrs = xAddrsMatch.Groups[1].Value.Trim();
          ExtractPortFromUrl(camera.XAddrs, camera);
        }

        var scopeMatch = System.Text.RegularExpressions.Regex.Match(
            response, "<d:Scopes>(.*?)</d:Scopes>", System.Text.RegularExpressions.RegexOptions.Singleline);
        if (scopeMatch.Success)
        {
          camera.Scopes = scopeMatch.Groups[1].Value.Trim();
          ExtractVendorFromScopes(camera.Scopes, camera);
        }

        var typesMatch = System.Text.RegularExpressions.Regex.Match(
            response, "<d:Types>(.*?)</d:Types>", System.Text.RegularExpressions.RegexOptions.Singleline);
        if (typesMatch.Success)
        {
          camera.Types = typesMatch.Groups[1].Value.Trim();
        }

        return camera;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"WS-Discovery解析失败: {ex.Message}");
        return null;
      }
    }

    private static DiscoveredCamera? ParseOnvifProbeResponse(string ip, string response)
    {
      try
      {
        if (!response.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase))
          return null;

        var camera = new DiscoveredCamera
        {
          Ip = ip,
          DiscoveryMethod = "ONVIF-Probe"
        };

        var xAddrsMatch = System.Text.RegularExpressions.Regex.Match(
            response, "<d:XAddrs>(.*?)</d:XAddrs>", System.Text.RegularExpressions.RegexOptions.Singleline);
        if (xAddrsMatch.Success)
        {
          camera.XAddrs = xAddrsMatch.Groups[1].Value.Trim();
          ExtractPortFromUrl(camera.XAddrs, camera);
        }

        var scopeMatch = System.Text.RegularExpressions.Regex.Match(
            response, "<d:Scopes>(.*?)</d:Scopes>", System.Text.RegularExpressions.RegexOptions.Singleline);
        if (scopeMatch.Success)
        {
          camera.Scopes = scopeMatch.Groups[1].Value.Trim();
          ExtractVendorFromScopes(camera.Scopes, camera);
        }

        camera.IsOnvif = true;

        return camera;
      }
      catch (Exception ex)
      {
        System.Diagnostics.Debug.WriteLine($"ONVIF Probe解析失败: {ex.Message}");
        return null;
      }
    }

    private static byte[] BuildMdnsQuery(string service)
    {
      var ms = new System.IO.MemoryStream();
      ms.Write(new byte[] { 0x00, 0x00 }, 0, 2);
      ms.Write(new byte[] { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, 10);

      var serviceBytes = Encoding.ASCII.GetBytes(service);
      ms.Write(serviceBytes, 0, serviceBytes.Length);
      ms.WriteByte(0x00);

      ms.Write(new byte[] { 0x00, 0x0C, 0x00, 0x01 }, 0, 4);

      return ms.ToArray();
    }

    private static byte[] BuildWsDiscoveryProbe()
    {
      var body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                 "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                 "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
                 "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" " +
                 "xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">" +
                 "<soap:Header>" +
                 "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" +
                 "<wsa:MessageID>urn:uuid:" + Guid.NewGuid().ToString() + "</wsa:MessageID>" +
                 "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>" +
                 "</soap:Header>" +
                 "<soap:Body>" +
                 "<wsd:Probe>" +
                 "<wsd:Types>wsdp:Device</wsd:Types>" +
                 "</wsd:Probe>" +
                 "</soap:Body>" +
                 "</soap:Envelope>";

      return Encoding.UTF8.GetBytes(body);
    }

    private static byte[] BuildOnvifProbeMessage()
    {
      var body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                 "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" " +
                 "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" " +
                 "xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" " +
                 "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">" +
                 "<soap:Header>" +
                 "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" +
                 "<wsa:MessageID>urn:uuid:" + Guid.NewGuid().ToString() + "</wsa:MessageID>" +
                 "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>" +
                 "</soap:Header>" +
                 "<soap:Body>" +
                 "<wsd:Probe>" +
                 "<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>" +
                 "</wsd:Probe>" +
                 "</soap:Body>" +
                 "</soap:Envelope>";

      return Encoding.UTF8.GetBytes(body);
    }

    private static void ExtractPortFromUrl(string url, DiscoveredCamera camera)
    {
      try
      {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
          camera.HttpPort = uri.Port;
        }
      }
      catch { }
    }

    private static void ExtractVendorFromServer(string server, DiscoveredCamera camera)
    {
      if (server.Contains("Hikvision", StringComparison.OrdinalIgnoreCase) ||
          server.Contains("HIKVISION", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Hikvision";
      else if (server.Contains("Dahua", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Dahua";
      else if (server.Contains("Axis", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Axis";
      else if (server.Contains("Bosch", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Bosch";
      else if (server.Contains("Panasonic", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Panasonic";
      else if (server.Contains("Sony", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Sony";
      else if (server.Contains("Samsung", StringComparison.OrdinalIgnoreCase) ||
               server.Contains("Wisenet", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Samsung";
      else if (server.Contains("Uniview", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Uniview";
      else if (server.Contains("Tiandy", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Tiandy";
      else if (server.Contains("TP-Link", StringComparison.OrdinalIgnoreCase) ||
               server.Contains("Tapo", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "TP-Link";
      else
        camera.Vendor = server.Length > 50 ? server.Substring(0, 50) : server;
    }

    private static void ExtractVendorFromScopes(string scopes, DiscoveredCamera camera)
    {
      if (scopes.Contains("hikvision", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Hikvision";
      else if (scopes.Contains("dahua", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Dahua";
      else if (scopes.Contains("axis", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Axis";
      else if (scopes.Contains("bosch", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Bosch";
      else if (scopes.Contains("panasonic", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Panasonic";
      else if (scopes.Contains("sony", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Sony";
      else if (scopes.Contains("samsung", StringComparison.OrdinalIgnoreCase) ||
               scopes.Contains("wisenet", StringComparison.OrdinalIgnoreCase) ||
               scopes.Contains("hanwha", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Samsung";
      else if (scopes.Contains("uniview", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Uniview";
      else if (scopes.Contains("tiandy", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "Tiandy";
      else if (scopes.Contains("tplink", StringComparison.OrdinalIgnoreCase) ||
               scopes.Contains("tapo", StringComparison.OrdinalIgnoreCase))
        camera.Vendor = "TP-Link";

      var nameMatch = System.Text.RegularExpressions.Regex.Match(
          scopes, "name/(.*?)(?:\\s|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
      if (nameMatch.Success)
      {
        camera.DeviceName = Uri.UnescapeDataString(nameMatch.Groups[1].Value.Trim());
      }

      var hwMatch = System.Text.RegularExpressions.Regex.Match(
          scopes, "hardware/(.*?)(?:\\s|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
      if (hwMatch.Success)
      {
        camera.Model = Uri.UnescapeDataString(hwMatch.Groups[1].Value.Trim());
      }
    }

    public void Dispose()
    {
      if (_disposed) return;
      _disposed = true;
      foreach (var client in _udpClients)
      {
        try { client.Dispose(); } catch { }
      }
      _udpClients.Clear();
    }
  }

  public class DiscoveredCamera
  {
    public string Ip { get; set; } = string.Empty;
    public string DiscoveryMethod { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string LocationUrl { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public string Usn { get; set; } = string.Empty;
    public string ServiceType { get; set; } = string.Empty;
    public string XAddrs { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public string Types { get; set; } = string.Empty;
    public int HttpPort { get; set; }
    public bool IsOnvif { get; set; }
  }
}