using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Api;

/// <summary>
/// Turns the raw registry facts loaded for one SBOM component into the small set of judgements the
/// component row renders: whether this registry serves the coordinate at all, whether it is
/// blocked, whether upstream has deprecated it, and whether the application is behind the version
/// the registry knows about.
///
/// <para><b>The server owns the judgement.</b> The UI renders chips; it never decides what
/// "outdated" means. That matters most for the version comparison, which is native per ecosystem —
/// a string compare would call <c>1.10.0</c> older than <c>1.9.0</c> and <c>1.0.0.0</c> different
/// from <c>1.0.0</c>.</para>
///
/// <para><b>Absence of a judgement is reported, never rounded to "fine".</b>
/// <see cref="ComponentRegistryView.Outdated"/> is a nullable bool: null means this ecosystem has
/// no native version ordering here, or one of the two versions did not parse under it, and the
/// caller renders the known upstream version as a neutral fact instead of an up-to-date verdict.
/// Likewise <see cref="RegistryPresence.Unknown"/> is its own state, distinct from
/// <see cref="RegistryPresence.Absent"/>: a component with no purl carries no coordinate the
/// registry could ever be asked about, and counting it as never-vetted would overstate the number
/// the operator is meant to act on.</para>
/// </summary>
public static class SbomRegistryView
{
    /// <summary>Both conditions are reported at this granularity when the shipped version matches.</summary>
    public const string ScopeVersion = "version";

    /// <summary>
    /// The coordinate carries the condition on some version, but not on the one this application
    /// ships — or the two version spellings could not be matched.
    /// </summary>
    public const string ScopePackage = "package";

    /// <summary>
    /// Builds the row's registry view from the facts loaded for its coordinate. Three outcomes, in
    /// order: no coordinate at all (the question cannot be asked), a coordinate this registry has
    /// never served (the blind spot), or the facts themselves.
    /// </summary>
    public static ComponentRegistryView For(
        string? ecosystem, string? purlName, string? componentVersion, ComponentRegistryFacts? facts) =>
        ecosystem is not { Length: > 0 } || purlName is not { Length: > 0 }
            ? ComponentRegistryView.Unknown
            : facts is null || !facts.Present
            ? ComponentRegistryView.Absent
            : new ComponentRegistryView(
                Presence: RegistryPresence.Present,
                Hosted: facts.Hosted,
                Cached: facts.Cached,
                Blocked: Scope(facts.BlockedThisVersion, facts.BlockedAnyVersion),
                Deprecated: Scope(facts.DeprecatedThisVersion, facts.DeprecatedAnyVersion),
                LatestVersion: facts.UpstreamLatestVersion,
                Outdated: IsOutdated(ecosystem, componentVersion, facts.UpstreamLatestVersion));

    private static string? Scope(bool thisVersion, bool anyVersion) =>
        thisVersion ? ScopeVersion : anyVersion ? ScopePackage : null;

    /// <summary>
    /// Whether the shipped version is strictly older than the latest version this registry knows
    /// upstream has. Null — unknown, never false — when there is no known upstream version, no
    /// shipped version, or the ecosystem has no native ordering registered
    /// (<see cref="EcosystemVersionOrdering.Compare"/> answers null for Go, RPM, OCI and Alpine,
    /// and for a version that fails to parse under a scheme that does exist).
    /// </summary>
    public static bool? IsOutdated(string ecosystem, string? componentVersion, string? latestVersion)
    {
        if (componentVersion is not { Length: > 0 } || latestVersion is not { Length: > 0 })
        {
            return null;
        }

        int? comparison = EcosystemVersionOrdering.Compare(ecosystem, componentVersion, latestVersion);
        return comparison is { } ordered ? ordered < 0 : null;
    }
}

/// <summary>Whether this tenant's registry has anything to say about a component's coordinate.</summary>
public static class RegistryPresence
{
    /// <summary>Served from the hosted catalogue, this tenant's proxy cache, or both.</summary>
    public const string Present = "present";

    /// <summary>
    /// A real coordinate the registry has never served — the blind spot: bytes the application
    /// ships that no policy gate of this registry has ever seen.
    /// </summary>
    public const string Absent = "absent";

    /// <summary>
    /// No purl, or a purl type with no registry mapping. The question cannot be asked, which is not
    /// the same answer as "no".
    /// </summary>
    public const string Unknown = "unknown";

    /// <summary>The values the <c>registry</c> row filter accepts, plus <c>all</c>.</summary>
    public static readonly IReadOnlySet<string> Filters =
        new HashSet<string>(StringComparer.Ordinal) { "all", Present, Absent, Unknown };
}

/// <summary>
/// The registry judgements attached to one component row. <see cref="Blocked"/> and
/// <see cref="Deprecated"/> are <c>null</c>, <see cref="SbomRegistryView.ScopeVersion"/>, or
/// <see cref="SbomRegistryView.ScopePackage"/>.
/// </summary>
public sealed record ComponentRegistryView(
    string Presence,
    bool Hosted,
    bool Cached,
    string? Blocked,
    string? Deprecated,
    string? LatestVersion,
    bool? Outdated)
{
    /// <summary>A real coordinate this registry has never served.</summary>
    public static readonly ComponentRegistryView Absent =
        new(RegistryPresence.Absent, false, false, null, null, null, null);

    /// <summary>A component carrying no coordinate the registry could be asked about.</summary>
    public static readonly ComponentRegistryView Unknown =
        new(RegistryPresence.Unknown, false, false, null, null, null, null);

    /// <summary>True when either registry plane serves this coordinate for this tenant.</summary>
    public bool InRegistry => string.Equals(Presence, RegistryPresence.Present, StringComparison.Ordinal);
}
