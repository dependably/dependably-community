namespace Dependably.Infrastructure;

/// <summary>
/// Single source of truth for which ecosystems the package-name claim model applies to.
/// <see cref="Enforced"/> is the set of ecosystems whose data paths actually consult
/// <see cref="ClaimResolver"/> (proxy-fetch gating and/or publish gating), so a claim on one of
/// them is a real control. The claims admin API accepts creates only for these; a claim on an
/// ecosystem nothing reads would be a silent no-op that reads as a security control, so it is
/// rejected rather than stored.
///
/// <see cref="ClaimAwareUnenforced"/> lists ecosystems that look claim-shaped (they have a purl
/// type and once appeared in the admin vocabulary) but whose read/publish paths do not consult
/// the resolver today, so the API can return a message that explains the gap rather than a bare
/// "unknown ecosystem".
/// </summary>
public static class ClaimEcosystems
{
    /// <summary>
    /// Ecosystems whose data paths consult <see cref="ClaimResolver"/>. Keep in lockstep with the
    /// actual resolver call sites — <c>ClaimVocabularyComplianceTests</c> fails when they drift.
    /// </summary>
    public static readonly IReadOnlySet<string> Enforced =
        new HashSet<string>(StringComparer.Ordinal) { "npm", "pypi", "nuget", "cargo" };

    /// <summary>
    /// Claim-shaped ecosystems whose data paths do not consult the resolver, kept only so the
    /// admin API can explain the difference between "not enforced" and "not an ecosystem".
    /// </summary>
    public static readonly IReadOnlySet<string> ClaimAwareUnenforced =
        new HashSet<string>(StringComparer.Ordinal) { "maven", "rpm", "oci" };

    /// <summary>Human-readable, comma-separated list of the enforced ecosystems for API messages.</summary>
    public const string AcceptedList = "npm, pypi, nuget, cargo";

    /// <summary>True when the ecosystem is claim-shaped but its data paths do not consult the resolver.</summary>
    public static bool IsClaimAware(string ecosystem) => ClaimAwareUnenforced.Contains(ecosystem);
}
