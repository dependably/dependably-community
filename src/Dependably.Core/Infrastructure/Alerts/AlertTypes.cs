namespace Dependably.Infrastructure.Alerts;

/// <summary>Closed vocabulary for <c>alert.type</c>, matching the schema CHECK constraint.</summary>
public static class AlertTypes
{
    /// <summary>Raised when <c>BlockGateService.QueueForReviewAsync</c> inserts a fresh quarantine row.</summary>
    public const string QuarantineNew = "quarantine_new";

    /// <summary>Raised when a scanned advisory meets the org's vulnerability severity threshold.</summary>
    public const string VulnSeverity = "vuln_severity";

    /// <summary>
    /// Raised when a scanned advisory is listed in the CISA Known Exploited Vulnerabilities
    /// catalog, independent of its CVSS severity (or lack of one). A distinct type from
    /// <see cref="VulnSeverity"/> — exploitation evidence and a CVSS band are different claims,
    /// and an org can enable/route them independently even though both currently share the
    /// <c>vuln_alerts_enabled</c> gate.
    /// </summary>
    public const string VulnKev = "vuln_kev";

    /// <summary>Raised when an SBOM policy evaluation records the first violation for a project version.</summary>
    public const string SbomPolicyViolation = "sbom_policy_violation";
}
