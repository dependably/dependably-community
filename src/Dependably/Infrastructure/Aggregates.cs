namespace Dependably.Infrastructure;

public class EcoCount { public string Ecosystem { get; set; } = ""; public int Count { get; set; } }
public class HourCount { public string Hour { get; set; } = ""; public int Count { get; set; } }
public class EcoSeverityCount { public string Ecosystem { get; set; } = ""; public string Severity { get; set; } = ""; public int Count { get; set; } }
public class EcoDiskBytes { public string Ecosystem { get; set; } = ""; public long TotalBytes { get; set; } }
public class VulnPeriodCounts { public int Day { get; set; } public int Week { get; set; } public int Month { get; set; } }

/// <summary>
/// SAML IdP signing-certificate expiry snapshot included in the org stats. Null when no cert
/// is configured. Computed live from the stored cert at stats-refresh time.
/// </summary>
public sealed class SamlCertExpiryStats
{
    /// <summary>Cert validity status: "ok", "expiring" (≤7d), or "expired".</summary>
    public string Status { get; set; } = "ok";
    /// <summary>Whole days remaining until cert expiry. Negative when already expired.</summary>
    public int DaysRemaining { get; set; }
    /// <summary>ISO 8601 UTC expiry timestamp.</summary>
    public string NotAfter { get; set; } = "";
}

public sealed record OrgStats(
    IReadOnlyList<EcoCount> PackagesByEcosystem,
    IReadOnlyList<HourCount> DownloadsByHour,
    IReadOnlyList<EcoSeverityCount> VulnsByEcosystemAndSeverity,
    IReadOnlyList<EcoDiskBytes> DiskByEcosystem,
    long TotalDiskBytes,
    VulnPeriodCounts NewVulns,
    int ActiveUsers7d,
    int BlockedPulls30d,
    int TotalDownloads30d,
    SamlCertExpiryStats? SamlCertExpiry = null);
