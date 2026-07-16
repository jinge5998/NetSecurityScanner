namespace NetSecurityScanner.Models
{
  public class CameraPortInfo
  {
    public int Port { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Banner { get; set; } = string.Empty;
    public bool IsDefaultPort { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
  }
}