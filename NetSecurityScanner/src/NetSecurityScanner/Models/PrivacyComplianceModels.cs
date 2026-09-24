using System.Collections.Generic;

namespace NetSecurityScanner.Models
{
  public class PrivacyComplianceReport
  {
    public double OverallScore { get; set; }
    public PrivacyManifestResult Manifest { get; set; } = new();
    public DataCollectionResult DataCollection { get; set; } = new();
    public TrackingSDKResult TrackingSDKs { get; set; } = new();
    public GDPRComplianceResult GDPR { get; set; } = new();
    public List<AppVulnerabilityResult> Vulnerabilities { get; set; } = new();
  }

  public class PrivacyManifestResult
  {
    public bool Detected { get; set; }
    public bool HasPrivacyManifest { get; set; }
    public bool HasPrivacyTrackingEnabled { get; set; }
    public bool HasPrivacyTrackingDomains { get; set; }
    public List<string> TrackingDomains { get; set; } = new();
    public bool HasRequiredReasonAPI { get; set; }
    public List<string> RequiredReasonAPIs { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class DataCollectionResult
  {
    public bool Detected { get; set; }
    public bool HasDataCollection { get; set; }
    public bool HasLocationCollection { get; set; }
    public bool HasCameraCollection { get; set; }
    public bool HasMicrophoneCollection { get; set; }
    public bool HasContactCollection { get; set; }
    public bool HasPhotoCollection { get; set; }
    public bool HasCalendarCollection { get; set; }
    public bool HasHealthDataCollection { get; set; }
    public bool HasBluetoothCollection { get; set; }
    public bool HasBiometricCollection { get; set; }
    public int TotalDataTypes { get; set; }
    public List<string> CollectedDataTypes { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class TrackingSDKResult
  {
    public bool Detected { get; set; }
    public bool HasGoogleAnalytics { get; set; }
    public bool HasFacebookSDK { get; set; }
    public bool HasFirebaseAnalytics { get; set; }
    public bool HasAdjust { get; set; }
    public bool HasAppsFlyer { get; set; }
    public bool HasMixpanel { get; set; }
    public bool HasAmplitude { get; set; }
    public bool HasSegment { get; set; }
    public int TotalTrackingSDKs { get; set; }
    public List<string> DetectedSDKs { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }

  public class GDPRComplianceResult
  {
    public bool Detected { get; set; }
    public bool HasConsentMechanism { get; set; }
    public bool HasDataRetentionPolicy { get; set; }
    public bool HasRightToDelete { get; set; }
    public bool HasDataPortability { get; set; }
    public bool HasDataProcessingAgreement { get; set; }
    public bool HasCrossBorderTransfer { get; set; }
    public bool HasAgeVerification { get; set; }
    public int ComplianceScore { get; set; }
    public List<string> ComplianceIndicators { get; set; } = new();
    public List<string> MissingRequirements { get; set; } = new();
    public string Confidence { get; set; } = "低";
  }
}