using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using NetSecurityScanner.Core.Models;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class CameraScanResultTests
    {
        [Fact]
        public void OverallRiskLevel_NoFindings_ReturnsInfo()
        {
            var result = new CameraScanResult();
            result.OverallRiskLevel.Should().Be("Info");
        }

        [Fact]
        public void OverallRiskLevel_OnlyCritical_ReturnsCritical()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.OverallRiskLevel.Should().Be("Critical");
        }

        [Fact]
        public void OverallRiskLevel_OnlyHigh_ReturnsHigh()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "High", CvssScore = 7.5 });
            result.OverallRiskLevel.Should().Be("High");
        }

        [Fact]
        public void OverallRiskLevel_OnlyMedium_ReturnsMedium()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Medium", CvssScore = 5.0 });
            result.OverallRiskLevel.Should().Be("Medium");
        }

        [Fact]
        public void OverallRiskLevel_OnlyLow_ReturnsLow()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Low", CvssScore = 3.0 });
            result.OverallRiskLevel.Should().Be("Low");
        }

        [Fact]
        public void OverallRiskLevel_CriticalAndHigh_ReturnsCritical()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "High", CvssScore = 7.5 });
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.OverallRiskLevel.Should().Be("Critical");
        }

        [Fact]
        public void RiskScore_NoFindings_Returns100()
        {
            var result = new CameraScanResult();
            result.RiskScore.Should().Be("100");
        }

        [Fact]
        public void RiskScore_OneCritical_Returns75()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.RiskScore.Should().Be("75");
        }

        [Fact]
        public void RiskScore_MultipleFindings_CalculatesCorrectly()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.Findings.Add(new CameraVulnFinding { Severity = "High", CvssScore = 7.5 });
            result.Findings.Add(new CameraVulnFinding { Severity = "Medium", CvssScore = 5.0 });
            result.RiskScore.Should().Be("52");
        }

        [Fact]
        public void RiskScore_ExcessiveFindings_ClampsToZero()
        {
            var result = new CameraScanResult();
            for (int i = 0; i < 5; i++)
                result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.RiskScore.Should().Be("0");
        }

        [Fact]
        public void CriticalCount_OnlyCountsCritical()
        {
            var result = new CameraScanResult();
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });
            result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 10.0 });
            result.Findings.Add(new CameraVulnFinding { Severity = "High", CvssScore = 7.5 });
            result.CriticalCount.Should().Be(2);
            result.HighRiskCount.Should().Be(1);
        }
    }

    public class CameraFingerprintTests
    {
        [Fact]
        public void HttpPatterns_IsListOfString()
        {
            var fp = new CameraFingerprint();
            fp.HttpPatterns.Should().BeAssignableTo<IList<string>>();
            fp.HttpPatterns.Should().BeEmpty();
        }

        [Fact]
        public void HttpServer_IsListOfString()
        {
            var fp = new CameraFingerprint();
            fp.HttpServer.Should().BeAssignableTo<IList<string>>();
        }

        [Fact]
        public void OnvifManufacturers_IsListOfString()
        {
            var fp = new CameraFingerprint();
            fp.OnvifManufacturers.Should().BeAssignableTo<IList<string>>();
        }

        [Fact]
        public void DefaultPorts_IsListOfInt()
        {
            var fp = new CameraFingerprint();
            fp.DefaultPorts.Should().BeAssignableTo<IList<int>>();
        }

        [Fact]
        public void Vendor_DefaultsToEmpty()
        {
            var fp = new CameraFingerprint();
            fp.Vendor.Should().BeEmpty();
        }
    }

    public class CameraVulnFindingTests
    {
        [Fact]
        public void AllProperties_DefaultInitialized()
        {
            var f = new CameraVulnFinding();
            f.CveId.Should().BeEmpty();
            f.Name.Should().BeEmpty();
            f.Description.Should().BeEmpty();
            f.Severity.Should().BeEmpty();
            f.CvssScore.Should().Be(0);
            f.Vendor.Should().BeEmpty();
            f.Confirmed.Should().BeFalse();
            f.Evidence.Should().BeEmpty();
            f.Endpoint.Should().BeEmpty();
            f.DetectionMethod.Should().BeEmpty();
            f.Remedy.Should().BeEmpty();
        }
    }

    public class CameraScanTargetTests
    {
        [Fact]
        public void DefaultValues_AreCorrect()
        {
            var t = new CameraScanTarget();
            t.IpAddress.Should().BeEmpty();
            t.Port.Should().Be(0);
            t.Protocol.Should().Be("http");
            t.DetectedVendor.Should().BeEmpty();
            t.IsReachable.Should().BeFalse();
            t.OpenPorts.Should().BeEmpty();
            t.PortServices.Should().BeEmpty();
        }
    }

    public class CameraVulnerabilityTests
    {
        [Fact]
        public void PoCEndpoints_DefaultsToEmptyList()
        {
            var v = new CameraVulnerability();
            v.PoCEndpoints.Should().BeEmpty();
            v.PoCMethod.Should().Be("GET");
        }
    }

    public class CameraWeakPasswordEntryTests
    {
        [Fact]
        public void DefaultLists_AreEmpty()
        {
            var e = new CameraWeakPasswordEntry();
            e.Usernames.Should().BeEmpty();
            e.Passwords.Should().BeEmpty();
            e.Vendor.Should().BeEmpty();
        }
    }

    public class CameraSecurityScannerConstructionTests
    {
        [Fact]
        public void Constructor_NullLogger_Throws()
        {
            Action act = () => new CameraSecurityScanner(null!);
            act.Should().Throw<ArgumentNullException>()
               .WithMessage("*logger*");
        }
    }

    public class CameraScanResultIntegrationTests
    {
        [Fact]
        public void FullScanResult_HighAndMedium_HighRiskLevel()
        {
            var result = new CameraScanResult
            {
                Target = new CameraScanTarget
                {
                    IpAddress = "192.168.1.1",
                    DetectedVendor = "Hikvision",
                    FirmwareVersion = "V5.4.0",
                    IsReachable = true,
                    OpenPorts = new List<int> { 80, 554, 8000 },
                    PortServices = new Dictionary<int, string> { { 80, "HTTP" }, { 554, "RTSP" }, { 8000, "Hikvision SDK" } }
                }
            };

            result.Findings.Add(new CameraVulnFinding
            {
                CveId = "CVE-2021-36260",
                Name = "命令注入",
                Severity = "High",
                CvssScore = 7.5,
                Vendor = "Hikvision",
                Confirmed = true,
                Remedy = "升级固件"
            });
            result.Findings.Add(new CameraVulnFinding
            {
                CveId = "RTSP-ANON-001",
                Name = "RTSP 未授权",
                Severity = "Medium",
                CvssScore = 5.0,
                Vendor = "Hikvision",
                Confirmed = true,
                Remedy = "启用认证"
            });

            result.OverallRiskLevel.Should().Be("High");
            result.HighRiskCount.Should().Be(1);
            result.MediumRiskCount.Should().Be(1);
            result.CriticalCount.Should().Be(0);
            int.Parse(result.RiskScore).Should().BeInRange(50, 100);
        }

        [Fact]
        public void FullScanResult_AllCritical_RiskScoreZero()
        {
            var result = new CameraScanResult();
            for (int i = 0; i < 4; i++)
                result.Findings.Add(new CameraVulnFinding { Severity = "Critical", CvssScore = 9.8 });

            result.OverallRiskLevel.Should().Be("Critical");
            result.RiskScore.Should().Be("0");
        }
    }
}