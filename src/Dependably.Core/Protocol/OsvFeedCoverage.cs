namespace Dependably.Protocol;

/// <summary>
/// Single source of truth for whether OSV publishes an advisory feed an artefact of a given
/// ecosystem could ever match.
///
/// The distinction matters because a stamped <c>vuln_checked_at</c> is what *enables* the
/// malicious/KEV/EPSS/CVSS block-gate arms, and because the UI reads that stamp as "screened,
/// nothing found". For an ecosystem OSV carries no feed for, a lookup returns an empty advisory
/// list no matter what the artefact contains — so stamping it records a clean bill of health that
/// no query could have produced, and renders identically to a package genuinely checked against a
/// live feed. Those artefacts are left unstamped and reported as <see cref="NoFeedStatus"/>
/// instead, which distinguishes "nothing to scan against" from "not scanned yet" — different
/// operator actions.
///
/// Membership is deliberately narrow: it names only the ecosystems OSV publishes no feed for at
/// all, never one whose advisories merely need a mapping. RPM is absent for exactly that reason —
/// OSV has no single "RPM" ecosystem, but it does publish distro feeds (Rocky Linux, AlmaLinux,
/// Red Hat) that a pkg:rpm query can resolve against upstream, so RPM keeps scanning and stamping.
/// </summary>
public static class OsvFeedCoverage
{
    /// <summary>
    /// Reported status for an artefact whose ecosystem has no advisory feed. Never "clean" — the
    /// absence of coverage is surfaced, not smoothed over.
    /// </summary>
    public const string NoFeedStatus = "no_feed";

    // OCI: image vulnerabilities are image-scan territory (Trivy), not OSV, which indexes
    // language-ecosystem packages. Terraform: OSV publishes no Terraform provider ecosystem at all.
    private static readonly string[] NoFeed = ["oci", "terraform"];

    /// <summary>
    /// Ecosystem names OSV publishes no advisory feed for, as stored in
    /// <c>packages.ecosystem</c> / <c>cache_artifact.ecosystem</c>. Bound as a Dapper list
    /// parameter by the scan queries so the exclusion has one definition rather than a literal
    /// per query.
    /// </summary>
    public static IReadOnlyList<string> NoFeedEcosystems => NoFeed;

    /// <summary>
    /// True when OSV publishes a feed this ecosystem's artefacts could match — the condition for
    /// querying it and, on a reached answer, stamping <c>vuln_checked_at</c>.
    /// An unknown or absent ecosystem answers true: the fail-safe direction is to scan and stamp
    /// (which keeps the gate's advisory arms enabled), never to silently skip screening.
    /// </summary>
    public static bool HasAdvisoryFeed(string? ecosystem) =>
        string.IsNullOrEmpty(ecosystem)
        || !NoFeed.Contains(ecosystem, StringComparer.OrdinalIgnoreCase);
}
