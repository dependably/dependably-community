using System.Diagnostics;

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

    /// <summary>
    /// True for the org-wide message (<see cref="ForOrg"/>), whose <see cref="Ecosystem"/> field
    /// carries the message kind <see cref="MetadataInvalidationEcosystems.Org"/> rather than an
    /// ecosystem id.
    /// </summary>
    public bool IsOrgWide => string.Equals(Ecosystem, MetadataInvalidationEcosystems.Org, StringComparison.Ordinal);

    /// <summary>
    /// The message's <c>scope</c> metric attribute: <see cref="MetadataInvalidationScopes.Org"/>
    /// for the org-wide message, <see cref="MetadataInvalidationScopes.Ecosystem"/> for a message
    /// that names one ecosystem's caches (RPM's tenant-wide message included).
    /// </summary>
    public string Scope => IsOrgWide ? MetadataInvalidationScopes.Org : MetadataInvalidationScopes.Ecosystem;

    /// <summary>
    /// The attributes every invalidation-counter measurement carries for this message, shared by
    /// the publish and receive sides. Always <c>scope</c>; <c>ecosystem</c> only for an
    /// ecosystem-scoped message, so the <c>ecosystem</c> attribute never holds a value outside
    /// the shared ecosystem vocabulary. The org id is never a tag. Callers add <c>outcome</c>
    /// where the instrument records one.
    /// </summary>
    public TagList MetricTags()
    {
        var tags = new TagList { new KeyValuePair<string, object?>("scope", Scope) };
        if (!IsOrgWide)
        {
            tags.Add(new KeyValuePair<string, object?>("ecosystem", Ecosystem));
        }

        return tags;
    }

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

    /// <summary>
    /// Org-wide invalidation: everything a replica has cached from the org's reserved namespaces
    /// and proxy settings (see <see cref="OrgWideCacheEviction"/>). Carries the org id and
    /// nothing else. A reservation pattern covers names that cannot be enumerated and a policy
    /// change can flip any version's advertised state, so there are no coordinates to name.
    /// </summary>
    public static MetadataInvalidation ForOrg(string orgId) =>
        new() { OrgId = orgId, Ecosystem = MetadataInvalidationEcosystems.Org };
}

/// <summary>
/// The wire vocabulary of <see cref="MetadataInvalidation.Ecosystem"/>: the values the codec
/// accepts and the coordinator expands. It is the message vocabulary only, not a metric label
/// set — the invalidation counters derive their attributes through
/// <see cref="MetadataInvalidation.MetricTags"/>, which emits <c>ecosystem</c> only for the real
/// ecosystem ids here and counts <see cref="Org"/> under <c>scope=org</c> instead. An
/// unrecognized value is dropped by the codec rather than applied.
///
/// <para><see cref="Org"/> is not an ecosystem but a message kind: the org-wide invalidation.
/// It travels in this field, rather than as a new optional field on an existing ecosystem's
/// message, because the codec of a build that predates it rejects an ecosystem it does not know.
/// During a rolling deploy the older replicas therefore drop the message and converge on TTL,
/// where an optional field they ignore would be read as a per-package message for whatever
/// ecosystem it rode on.</para>
/// </summary>
public static class MetadataInvalidationEcosystems
{
    public const string Npm = "npm";
    public const string PyPi = "pypi";
    public const string NuGet = "nuget";
    public const string Maven = "maven";
    public const string Rpm = "rpm";

    /// <summary>The org-wide message kind; see <see cref="MetadataInvalidation.ForOrg"/>.</summary>
    public const string Org = "org";

    /// <summary>Every recognized value, in declaration order.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Npm, PyPi, NuGet, Maven, Rpm, Org };

    /// <summary>True when <paramref name="ecosystem"/> is one this instance knows how to expand.</summary>
    public static bool IsKnown(string? ecosystem) =>
        ecosystem is not null && All.Contains(ecosystem, StringComparer.Ordinal);
}

/// <summary>
/// The bounded <c>scope</c> attribute on the invalidation counters: which kind of cache set a
/// message clears.
/// </summary>
public static class MetadataInvalidationScopes
{
    /// <summary>A message naming one ecosystem's caches (npm, PyPI, NuGet, Maven, RPM).</summary>
    public const string Ecosystem = "ecosystem";

    /// <summary>The org-wide message; see <see cref="MetadataInvalidation.ForOrg"/>.</summary>
    public const string Org = "org";

    /// <summary>Every value, in declaration order.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Ecosystem, Org };
}
