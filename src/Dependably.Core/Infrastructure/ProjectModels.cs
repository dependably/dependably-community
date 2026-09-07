namespace Dependably.Infrastructure;

/// <summary>The <c>projects.kind</c> discriminator vocabulary.</summary>
public static class ProjectKinds
{
    /// <summary>An application or service a team builds. Holds versions and accepts uploads.</summary>
    public const string Project = "project";

    /// <summary>A grouping of projects. Holds no versions and accepts no uploads.</summary>
    public const string Collection = "collection";

    /// <summary>The kinds a caller may name.</summary>
    public static readonly IReadOnlyList<string> All = [Project, Collection];

    public static bool IsKnown(string? kind) =>
        kind is not null && All.Contains(kind, StringComparer.Ordinal);
}

/// <summary>
/// The CycloneDX <c>component.type</c> vocabulary <c>projects.classifier</c> carries. The column has
/// no CHECK, so this list is the only place the accepted set is written down.
///
/// The two entry points treat an unrecognised value differently on purpose.
/// <see cref="IsKnown"/> backs the API's create validation, which refuses one outright: a typo in a
/// hand-written request is worth a 422. <see cref="Coerce"/> backs SBOM ingest, which falls back to
/// <see cref="Default"/>: a document must never fail to ingest over a cosmetic label, and a
/// CycloneDX release that adds a type would otherwise start rejecting valid SBOMs.
/// </summary>
public static class ProjectClassifiers
{
    /// <summary>The classifier a project gets when nothing names one.</summary>
    public const string Default = "application";

    /// <summary>CycloneDX <c>component.type</c>. The vocabulary is unchanged from 1.4 through 1.7.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        "application", "framework", "library", "container", "platform", "operating-system",
        "device", "device-driver", "firmware", "file", "machine-learning-model", "data",
        "cryptographic-asset",
    ];

    public static bool IsKnown(string? classifier) =>
        classifier is not null && All.Contains(classifier, StringComparer.Ordinal);

    /// <summary>Returns the classifier when it is recognised, else <see cref="Default"/>.</summary>
    public static string Coerce(string? classifier)
    {
        string? trimmed = classifier?.Trim();
        return IsKnown(trimmed) ? trimmed! : Default;
    }
}

/// <summary>
/// The one place "is this project version still something the tenant ships" is written down.
///
/// <para>Two independent flags decide it. <c>projects.is_active</c> retires a whole application —
/// decommissioned, handed to another team, deleted in everything but name — and <c>
/// project_versions.is_active</c> retires one release of an application that is still running.
/// A version is in service when its project is active AND the version is either the project's
/// latest or has been kept active; both flags default to on, so nothing an operator has not
/// triaged silently drops out of a security count.</para>
///
/// <para><b>Why <c>is_latest</c> stays in the predicate at all.</b> Dropping it would make the
/// answer depend entirely on a flag an operator has to maintain, and the release nobody has
/// touched yet is exactly the one an SBOM upload just created. Latest is the floor: the current
/// build is in service whether or not anyone has said so.</para>
///
/// <para>The SQL fragments are constants rather than repeated literals because the predicate has
/// to hold identically across the blast-radius reads, the nightly re-evaluation sweep and the
/// retention cap. Those three disagreeing is not a cosmetic drift — it is a version that is
/// counted but never rescanned (a stale number on a security surface), or one that is counted
/// and then deleted out from under the count.</para>
/// </summary>
public static class ProjectLifecycle
{
    /// <summary>
    /// The in-service predicate, written for a query that has joined <c>projects</c> as
    /// <c>p</c> and <c>project_versions</c> as <c>pv</c>. Callers concatenate it into a WHERE
    /// clause; it binds no parameters.
    /// </summary>
    public const string InServiceFilter =
        "p.is_active = 1 AND (pv.is_latest = 1 OR pv.is_active = 1)";

    /// <summary>
    /// The join a query needs before <see cref="InServiceFilter"/> can be applied, for the reads
    /// that previously reached <c>project_versions</c> without touching <c>projects</c> at all.
    /// Carries the tenant column so the join cannot widen the org scope the caller established.
    /// </summary>
    public const string ProjectJoin =
        "JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id";

    /// <summary>
    /// True when a version with these flags is one the tenant still ships. The C# mirror of
    /// <see cref="InServiceFilter"/>, for callers holding rows rather than writing SQL.
    /// </summary>
    public static bool IsInService(bool projectActive, bool versionIsLatest, bool versionActive) =>
        projectActive && (versionIsLatest || versionActive);
}

/// <summary>
/// Advisory findings for one project version, bucketed by severity. An advisory carrying no CVSS
/// classification lands in <see cref="Unscored"/> rather than being folded into a severity it was
/// never assigned — the security surfaces render that as UNSCORED, never as a blank or a guess.
/// </summary>
public sealed class SeverityCounts
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Unscored { get; set; }

    /// <summary>
    /// Component-advisory pairs whose advisory is listed in the CISA Known Exploited
    /// Vulnerabilities Catalog — the same signal the severity buckets count, filtered to
    /// <c>vulnerabilities.is_kev</c> rather than <c>severity</c>, and subject to the same
    /// VEX-suppression exclusion so a suppressed advisory never lights this up either.
    /// </summary>
    public int KevCount { get; set; }

    /// <summary>Folds one <c>vulnerabilities.severity</c> group into the matching bucket.</summary>
    public void Add(string? severity, int count)
    {
        switch (severity)
        {
            case "CRITICAL": Critical += count; break;
            case "HIGH": High += count; break;
            case "MEDIUM": Medium += count; break;
            case "LOW": Low += count; break;
            default: Unscored += count; break;
        }
    }
}

/// <summary>
/// How a collection's own policy verdict is derived from the projects beneath it.
///
/// Worst-wins, with one deliberate asymmetry: **a NULL descendant blocks `pass`.** NULL means
/// never evaluated, which is not the same statement as passing (see the plane's `warn` rule), so a
/// folder that reported `pass` while holding a project nobody had scanned would be claiming a
/// clean bill of health it has no evidence for — and folders are exactly where an operator looks
/// to avoid reading every row. It does not block `violation` or `warn`: those are already the
/// worse answer, and downgrading a real violation to "unknown" because a sibling is unscanned
/// would hide the finding this rollup exists to surface.
/// </summary>
public static class ProjectPolicyRollup
{
    /// <summary>Ordered worst-first; the first one present wins outright.</summary>
    public const string Violation = "violation";

    public const string Warn = "warn";

    public const string Pass = "pass";

    /// <summary>
    /// Folds one descendant verdict per project — its <c>is_latest</c> version's
    /// <c>policy_status</c>, or null for a project holding no version at all, which reads as
    /// "Not scanned" on its own row and must read the same way through a folder.
    /// Returns null for an empty collection: nothing beneath it has been evaluated.
    /// </summary>
    public static string? Worst(IEnumerable<string?> descendantStatuses)
    {
        bool sawUnevaluated = false;
        bool sawWarn = false;
        bool sawPass = false;

        foreach (string? status in descendantStatuses)
        {
            switch (status)
            {
                case Violation: return Violation;
                case Warn: sawWarn = true; break;
                case Pass: sawPass = true; break;
                // Null, and anything outside the vocabulary. A value this fold does not recognise
                // is not evidence of a pass, so it must not license one — the safe direction, at
                // the cost that a status added later degrades to "Not scanned" here until it is
                // given an arm rather than announcing itself.
                default: sawUnevaluated = true; break;
            }
        }

        return sawWarn ? Warn
            : sawPass && !sawUnevaluated ? Pass
            : null;
    }
}

/// <summary>
/// The rollup a collection carries: the sum of its whole subtree, not merely its direct children.
/// A folder holding only folders would otherwise report zeros while the projects two levels down
/// carry every component and every finding.
/// </summary>
public sealed class ProjectSubtreeRollup
{
    /// <summary>Descendant projects (<c>kind = 'project'</c>) at any depth beneath this row.</summary>
    public int ProjectCount { get; set; }

    /// <summary>
    /// How many of those projects contributed no verdict — no version at all, or a latest version
    /// nobody has evaluated. This is what makes a folder's "Not scanned" readable: without it,
    /// 49-passing-and-1-unscanned renders identically to a folder nobody has ever touched, and a
    /// reader facing an unexplained grey badge over a screen of green children concludes the badge
    /// is broken. It is also the only actionable number in the rollup — a status is a state, a
    /// count is a to-do list.
    /// </summary>
    public int UnevaluatedProjectCount { get; set; }

    /// <summary>Components across each descendant project's <c>is_latest</c> version.</summary>
    public int ComponentCount { get; set; }

    public SeverityCounts SeverityCounts { get; set; } = new();

    /// <summary>Worst-wins across the subtree — see <see cref="ProjectPolicyRollup"/>.</summary>
    public string? PolicyStatus { get; set; }

    /// <summary>The most recent upload anywhere beneath this row.</summary>
    public DateTimeOffset? LastUploadAt { get; set; }
}

/// <summary>
/// One row of the projects list: the project plus the read-time rollup of its <c>is_latest</c>
/// version. A collection, and a project with no latest version, carries a null version label with
/// zeroed counts.
/// </summary>
public sealed class ProjectListRow
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = ProjectKinds.Project;
    public string Classifier { get; set; } = ProjectClassifiers.Default;
    public string? ParentId { get; set; }
    public string? ParentName { get; set; }

    /// <summary>Whether the application is still in service. Retiring it empties its blast radius.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>The <c>is_latest</c> version's id; null when the project has no versions.</summary>
    public string? LatestVersionId { get; set; }
    public string? LatestVersion { get; set; }

    /// <summary>The latest version's policy verdict. Null means never evaluated, not "pass".</summary>
    public string? PolicyStatus { get; set; }

    public int ComponentCount { get; set; }
    public SeverityCounts SeverityCounts { get; set; } = new();

    /// <summary>
    /// For a collection, the projects beneath it and how many of those carry no verdict — the same
    /// pair the detail page's rollup reports, so the list badge is as readable as the detail one.
    /// Null on a project row, which summarizes only itself and has nothing to count.
    /// </summary>
    public int? SubtreeProjectCount { get; set; }

    public int? SubtreeUnevaluatedProjectCount { get; set; }

    /// <summary>The most recent document upload across every version of this project.</summary>
    public DateTimeOffset? LastUploadAt { get; set; }
}

/// <summary>One name-search hit: just enough to render a global-search result row and link into it.</summary>
public sealed class ProjectSearchRow
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = ProjectKinds.Project;
}

/// <summary>One version row on the project-detail surface.</summary>
public sealed class ProjectVersionSummary
{
    public string Id { get; set; } = "";
    public string Version { get; set; } = "";
    public bool IsLatest { get; set; }

    /// <summary>Whether this release is still deployed. Independent of <see cref="IsLatest"/>.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Null means never evaluated, which is not the same as passing.</summary>
    public string? PolicyStatus { get; set; }
    public int ComponentCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// One ancestor on a project's root-to-parent path. The breadcrumb surfaces render this chain so a
/// reader nested inside a collection can climb back out; a root-level project's chain is empty.
/// </summary>
public sealed class ProjectPathEntry
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>
/// One collection the org holds, flat and unpaged. This backs the relocation picker, which needs
/// every collection at once (it renders each as a full path) rather than one page of root rows.
/// </summary>
public sealed class ProjectCollectionRow
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? ParentId { get; set; }
}

/// <summary>
/// One descendant project of a collection, as an aggregate export names it: the project's own
/// identity plus the single version the export selected for it. A null
/// <see cref="ProjectVersionId"/> means the project holds no latest version — it is still listed,
/// because a document that omits a project the folder contains claims a completeness it does not
/// have.
/// </summary>
public sealed class ProjectSubtreeEntry
{
    public string ProjectId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Classifier { get; set; } = ProjectClassifiers.Default;
    public string? ProjectVersionId { get; set; }
    public string? VersionLabel { get; set; }
}

/// <summary>
/// One child row on a collection's detail surface. A child that is itself a collection carries its
/// own subtree rollup in <see cref="ComponentCount"/>/<see cref="SeverityCounts"/>/
/// <see cref="PolicyStatus"/>, so the numbers read the same way at every level of the tree.
/// </summary>
public sealed class ProjectChildSummary
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = ProjectKinds.Project;

    /// <summary>Whether the child application is still in service.</summary>
    public bool IsActive { get; set; } = true;

    public string? LatestVersion { get; set; }
    public string? PolicyStatus { get; set; }

    /// <summary>Set by the read path; see <see cref="LatestVersionId"/> for where it comes from.</summary>
    public int ComponentCount { get; set; }

    public SeverityCounts SeverityCounts { get; set; } = new();

    /// <summary>The <c>is_latest</c> version's id, or null for a collection and an empty project.</summary>
    public string? LatestVersionId { get; set; }
}

/// <summary>
/// The outcome of <see cref="ProjectRepository.ResolveOrCreateAsync"/>: the coordinate the caller
/// asked for, plus whether reaching it required creating anything.
/// </summary>
public sealed class ProjectResolution
{
    public string ProjectId { get; set; } = "";
    public string ProjectVersionId { get; set; } = "";
    public string ProjectName { get; set; } = "";
    public string VersionLabel { get; set; } = "";
    public bool ProjectCreated { get; set; }
    public bool VersionCreated { get; set; }
}

/// <summary>
/// Why <see cref="ProjectRepository.ResolveOrCreateAsync"/> could not reach the requested
/// coordinate. The caller maps each to its own status code — see
/// <see cref="ProjectResolutionException"/>.
/// </summary>
public enum ProjectResolutionReason
{
    /// <summary>The project or version does not exist and auto-create was not requested — 404.</summary>
    NotFound,

    /// <summary>The resolved project is a collection, which holds no versions — 409.</summary>
    CollectionTarget,

    /// <summary>The named parent exists but is a project rather than a collection — 409.</summary>
    ParentNotACollection,

    /// <summary>The named parent does not exist and auto-create was not requested — 404.</summary>
    ParentNotFound,

    /// <summary>A relocation named the project itself as its own parent — 422.</summary>
    ParentIsSelf,

    /// <summary>
    /// A relocation named one of the project's own descendants as its parent, which would detach
    /// the whole subtree into a cycle unreachable from the root — 422.
    /// </summary>
    ParentIsDescendant,

    /// <summary>The target parent scope already holds a different project of this name — 409.</summary>
    NameTaken,
}

/// <summary>
/// Raised when a project coordinate cannot be resolved or created. <see cref="Reason"/> is the
/// discriminator callers switch on; the message is diagnostic text, never a response body — API
/// callers render a localized problem detail from the reason.
/// </summary>
/// <summary>
/// The fields that describe a project being created. Grouped into one value because the create
/// path threads them through three layers — controller, repository, insert helper — and a
/// positional list of five nullable strings is a signature callers get wrong silently.
/// </summary>
public sealed record NewProject(
    string Name,
    string Kind,
    string? Classifier = null,
    string? Description = null,
    string? ParentId = null);

/// <summary>The coordinate of a project version being inserted.</summary>
public sealed record NewProjectVersion(string ProjectId, string Version, bool IsLatest);

/// <summary>
/// One "resolve this project version, creating it if allowed" request. Same reason as
/// <see cref="NewProject"/>: the parent may be named by id or by name, and the two are not
/// interchangeable, so the pair travels together rather than as adjacent nullable strings.
/// </summary>
public sealed record ProjectVersionRequest(
    string ProjectName,
    string ProjectVersion,
    bool AutoCreate,
    string? ParentId = null,
    string? ParentName = null,
    string? ParentVersion = null,
    bool IsLatest = true,
    string? Classifier = null);

[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ProjectResolutionException : Exception
{
    public ProjectResolutionException(ProjectResolutionReason reason, string message)
        : base(message) => Reason = reason;

    public ProjectResolutionException(ProjectResolutionReason reason, string message, Exception inner)
        : base(message, inner) => Reason = reason;

    public ProjectResolutionReason Reason { get; }
}
