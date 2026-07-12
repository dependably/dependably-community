namespace Dependably.Infrastructure.Alerts;

/// <summary>Closed vocabulary for <c>alert.type</c>, matching the schema CHECK constraint.</summary>
public static class AlertTypes
{
    /// <summary>Raised when <c>BlockGateService.QueueForReviewAsync</c> inserts a fresh quarantine row.</summary>
    public const string QuarantineNew = "quarantine_new";

    /// <summary>Raised when a scanned advisory meets the org's vulnerability severity threshold.</summary>
    public const string VulnSeverity = "vuln_severity";
}
