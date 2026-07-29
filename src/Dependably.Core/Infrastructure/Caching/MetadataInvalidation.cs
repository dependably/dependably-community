namespace Dependably.Infrastructure.Caching;

/// <summary>
/// The coordinates of one rendered-metadata invalidation: which tenant, which ecosystem, and
/// which package the mutation touched. Deliberately carries <em>coordinates</em> rather than
/// formatted cache keys — the receiving replica expands them through
/// <see cref="MetadataInvalidationCoordinator"/>, which is the one place that knows an
/// ecosystem's full variant matrix (npm local/proxy, PyPI HTML/JSON, NuGet SemVer1/2 × local/proxy,
/// Maven artifact-level/version-level, RPM local documents + merged tuple). Shipping keys instead
/// would let a publisher on an older build ship a variant set the receiver no longer agrees with;
/// shipping coordinates keeps the expansion on the side that owns the caches.
/// </summary>
/// <remarks>
/// Construct through the per-ecosystem factories rather than the initializer so a call site
/// cannot omit a coordinate an ecosystem needs — the same reasoning as the
/// <c>BlockGateRequest</c> factories.
/// </remarks>
public sealed record MetadataInvalidation
{
    /// <summary>Owning tenant. Every rendered-cache key is org-scoped.</summary>
    public required string OrgId { get; init; }

    /// <summary>One of <see cref="MetadataInvalidationEcosystems"/>.</summary>
    public required string Ecosystem { get; init; }

    /// <summary>
    /// Package identity for the single-package ecosystems: the npm full (scoped) name, the raw
    /// PyPI project name (normalized by the key formatter, not here), or the NuGet id.
    /// <see langword="null"/> for RPM, whose repodata documents are tenant-wide.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>Maven groupId; <see langword="null"/> for every other ecosystem.</summary>
    public string? GroupId { get; init; }

    /// <summary>Maven artifactId; <see langword="null"/> for every other ecosystem.</summary>
    public string? ArtifactId { get; init; }

    /// <summary>
    /// Maven SNAPSHOT version whose version-level <c>maven-metadata.xml</c> also changed;
    /// <see langword="null"/> when only the artifact-level document is affected.
    /// </summary>
    public string? Version { get; init; }

    /// <summary>npm packument invalidation for <paramref name="fullName"/> (scope included).</summary>
    public static MetadataInvalidation ForNpm(string orgId, string fullName) =>
        new() { OrgId = orgId, Ecosystem = MetadataInvalidationEcosystems.Npm, Name = fullName };

    /// <summary>
    /// PyPI simple-index invalidation. <paramref name="name"/> is the raw project name — the key
    /// formatter owns PEP 503 normalization, so passing the raw spelling is correct here.
    /// </summary>
    public static MetadataInvalidation ForPyPi(string orgId, string name) =>
        new() { OrgId = orgId, Ecosystem = MetadataInvalidationEcosystems.PyPi, Name = name };

    /// <summary>
    /// NuGet registration-index invalidation. <paramref name="id"/> is the package id; the
    /// coordinator lower-cases it to the normalized PURL name the registration key uses.
    /// </summary>
    public static MetadataInvalidation ForNuGet(string orgId, string id) =>
        new() { OrgId = orgId, Ecosystem = MetadataInvalidationEcosystems.NuGet, Name = id };

    /// <summary>
    /// Maven metadata invalidation. Pass <paramref name="version"/> only for a SNAPSHOT publish,
    /// whose version-level document reports a build list that the new file changes; a release
    /// publish affects the artifact-level document alone.
    /// </summary>
    public static MetadataInvalidation ForMaven(string orgId, string groupId, string artifactId, string? version = null) =>
        new()
        {
            OrgId = orgId,
            Ecosystem = MetadataInvalidationEcosystems.Maven,
            GroupId = groupId,
            ArtifactId = artifactId,
            Version = version,
        };

    /// <summary>
    /// RPM repodata invalidation — tenant-wide. RPM has no per-package rendered document: a
    /// single publish rewrites the tenant's primary/filelists/other documents and the merged
    /// tuple, so the coordinates stop at the org.
    /// </summary>
    public static MetadataInvalidation ForRpm(string orgId) =>
        new() { OrgId = orgId, Ecosystem = MetadataInvalidationEcosystems.Rpm };
}

/// <summary>
/// The bounded ecosystem vocabulary carried on <see cref="MetadataInvalidation.Ecosystem"/> and
/// used as the <c>ecosystem</c> metric attribute on the invalidation counters. Bounded by
/// construction — an unrecognized value is dropped by the coordinator rather than passed through
/// to a metric label.
/// </summary>
public static class MetadataInvalidationEcosystems
{
    public const string Npm = "npm";
    public const string PyPi = "pypi";
    public const string NuGet = "nuget";
    public const string Maven = "maven";
    public const string Rpm = "rpm";

    /// <summary>Every recognized ecosystem, in declaration order.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Npm, PyPi, NuGet, Maven, Rpm };

    /// <summary>True when <paramref name="ecosystem"/> is one this instance knows how to expand.</summary>
    public static bool IsKnown(string? ecosystem) =>
        ecosystem is not null && All.Contains(ecosystem, StringComparer.Ordinal);
}
