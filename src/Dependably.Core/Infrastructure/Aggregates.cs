namespace Dependably.Infrastructure;

public class EcoCount { public string Ecosystem { get; set; } = ""; public int Count { get; set; } }
public class HourCount { public string Hour { get; set; } = ""; public int Count { get; set; } }
public class EcoSeverityCount { public string Ecosystem { get; set; } = ""; public string Severity { get; set; } = ""; public int Count { get; set; } }
public class EcoDiskBytes { public string Ecosystem { get; set; } = ""; public long TotalBytes { get; set; } }
public class VulnPeriodCounts { public int Day { get; set; } public int Week { get; set; } public int Month { get; set; } }

/// <summary>
/// One supply-chain block gate's 30-day count. <see cref="Gate"/> is the gate name with the
/// <c>blocked_</c> prefix stripped (e.g. "malicious", "kev", "epss", "deprecated",
/// "release_age", "vuln_score", "manual"); the legacy bare <c>blocked</c> event maps to "manual".
/// </summary>
public class GateCount { public string Gate { get; set; } = ""; public int Count { get; set; } }

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
    SamlCertExpiryStats? SamlCertExpiry = null,
    // Fields below are appended with defaults so org_stats_snapshot rows serialized before they
    // existed still deserialize (stale rows read as empty/0 until the next refresh overwrites them).
    IReadOnlyList<GateCount>? BlockedByGate30d = null,
    int QuarantinePending = 0,
    int HostedPackages = 0,
    int ProxiedPackages = 0,
    long? StorageQuotaBytes = null,
    // Operational-risk pillar: distinct packages carrying at least one version whose
    // versions_behind meets or exceeds VersionsBehindThreshold. A NULL versions_behind (unknown)
    // never counts toward this — the signal only fires on a known, high count.
    int OperationalRiskPackageCount = 0,
    int VersionsBehindThreshold = 0,
    // License-risk pillar: distinct versions carrying either a blocklisted SPDX license or no
    // extracted license at all (unknown).
    int LicenseRiskVersionCount = 0);

/// <summary>
/// One version behind upstream, as listed by the operational-risk drill-down. Rows come from
/// both storage planes: uploaded versions (<c>package_versions</c>) and proxied artifacts
/// (<c>cache_artifact</c>, org-scoped through <c>tenant_artifact_access</c>).
/// <see cref="Name"/> is the normalized purl name and is the key the version-detail route is
/// built from; <see cref="DisplayName"/> is the human-facing package name, which falls back to
/// <see cref="Name"/> for a proxied artifact with no per-org <c>packages</c> row.
/// </summary>
public sealed class OperationalRiskRow
{
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? Purl { get; set; }
    public string Version { get; set; } = "";
    public long VersionsBehind { get; set; }
    public string Origin { get; set; } = "";
    public string? UpstreamLatestVersion { get; set; }
    public string? PublishedAt { get; set; }
    public string? Deprecated { get; set; }
    public string? RevokedAt { get; set; }
}

/// <summary>
/// One version at license risk, as listed by the license drill-down. <see cref="Reason"/> is
/// "blocklisted" (the version carries an SPDX identifier on the org's blocklist) or "unknown"
/// (no license could be extracted at all) — the two populations the single dashboard tile counts.
/// The SPDX identifiers themselves are stitched on by the caller, keyed by
/// <see cref="OwnerId"/> within the row's <see cref="OwnerKind"/> plane.
/// <see cref="Filename"/> distinguishes the several proxied artifacts a single Maven
/// (name, version) can carry.
/// </summary>
public sealed class LicenseRiskRow
{
    public string OwnerKind { get; set; } = "";
    public string OwnerId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? Purl { get; set; }
    public string Version { get; set; } = "";
    public string? Filename { get; set; }
    public string Origin { get; set; } = "";
    public string? PublishedAt { get; set; }
    public string Reason { get; set; } = "";
}
