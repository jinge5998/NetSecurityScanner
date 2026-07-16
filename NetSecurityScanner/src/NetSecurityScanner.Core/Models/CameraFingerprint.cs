namespace NetSecurityScanner.Models
{
  public class CameraFingerprint
  {
    public string Vendor { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string FirmwareVersion { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string HttpServer { get; set; } = string.Empty;
    public string LocationUrl { get; set; } = string.Empty;
    public string OnvifVersion { get; set; } = string.Empty;
    public double Confidence { get; set; }
  }
}