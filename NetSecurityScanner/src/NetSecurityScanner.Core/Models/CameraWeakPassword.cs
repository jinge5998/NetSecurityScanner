namespace NetSecurityScanner.Models
{
  public class CameraWeakPassword
  {
    public string ServiceType { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string RiskLevel { get; set; } = string.Empty;
    public string Suggestion { get; set; } = string.Empty;
  }
}