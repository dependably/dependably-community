using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// The reverse of the component cross-link: given a registry coordinate or an advisory, which of
/// this tenant's applications ship it.
///
/// <para>This is the read that justifies SBOM management living inside a registry. Every other
/// query on the projects plane starts from a project version and walks outwards; this one starts
/// from a package an operator has just quarantined, or an advisory that just landed, and answers
/// "which of my applications are affected". The hops are all indexed —
/// <c>vulnerabilities → sbom_component_vulns(vuln_id) → sbom_components(org_id, ecosystem,
/// purl_name) → project_versions(is_latest) → projects</c> — and
/// <c>idx_sbom_components_org_eco_name</c> exists for exactly this direction.</para>
///
/// <para><b>Read-time join, never a materialized link.</b> A stored "this package is used by N
/// applications" column goes stale in both directions: publishing or deleting a package changes
/// nothing on the projects plane that would invalidate it, and re-uploading an SBOM changes
/// nothing on the registry plane. The join is cheap and always current; the flag would be neither.
/// </para>
///
/// <para><b>Latest versions only.</b> Every query here filters <c>project_versions.is_latest = 1</c>.
/// The question being asked is "what am I shipping now", and an older release of an application is
/// not something an operator can remediate — the fix lands in the next release, not in a version
/// already cut. There is a correctness reason too: the nightly component scan only refreshes the
/// advisory links of <c>is_latest</c> versions, so a superseded version's
/// <c>sbom_component_vulns</c> rows are a snapshot of whenever it last was latest. Counting them
/// would mix a current answer with a stale one under a single number and give an operator no way
/// to tell which was which.</para>
/// </summary>
public sealed class SbomBlastRadiusRepository
{
    /// <summary>Largest page of affected applications a caller may request.</summary>
    public const int MaxPageSize = 200;

    /// <summary>Page size applied when the caller names none.</summary>
    public const int DefaultPageSize = 50;

    /// <summary>
    /// Largest batch of keys the count endpoint answers in one request. Bounds the parameter list
    /// the expanded <c>IN</c> becomes, and matches the largest page any caller renders.
    /// </summary>
    public const int MaxCountKeys = 200;

    private readonly IMetadataStore _db;

    public SbomBlastRadiusRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// The latest versions of this tenant's applications whose SBOM lists
    /// <paramref name="ecosystem"/>/<paramref name="purlName"/>, plus both totals.
    /// </summary>
    public async Task<BlastRadiusPage> ListByCoordinateAsync(
        string orgId, string ecosystem, string purlName, int limit, int offset, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var parameters = new { orgId, ecosystem, purlName, limit, offset };
        var totals = await conn.QuerySingleAsync<BlastRadiusTotalsRow>(new CommandDefinition(
            """
            SELECT COUNT(*) AS RowTotal, COUNT(DISTINCT pv.project_id) AS ProjectTotal
            FROM sbom_components c
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            WHERE c.org_id = @orgId AND c.ecosystem = @ecosystem AND c.purl_name = @purlName
              AND pv.is_latest = 1
            """,
            parameters, cancellationToken: ct));

        var rows = await conn.QueryAsync<BlastRadiusRow>(new CommandDefinition(
            """
            SELECT p.id             AS ProjectId,
                   p.name           AS ProjectName,
                   p.classifier     AS Classifier,
                   pv.id            AS ProjectVersionId,
                   pv.version       AS ProjectVersion,
                   pv.policy_status AS PolicyStatus,
                   c.version        AS ComponentVersion,
                   c.purl           AS ComponentPurl,
                   c.dependency_scope AS DependencyScope
            FROM sbom_components c
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
            WHERE c.org_id = @orgId AND c.ecosystem = @ecosystem AND c.purl_name = @purlName
              AND pv.is_latest = 1
            ORDER BY p.name, pv.version, c.id
            LIMIT @limit OFFSET @offset
            """,
            parameters, cancellationToken: ct));
        return new BlastRadiusPage(rows.ToList(), totals.RowTotal, totals.ProjectTotal);
    }

    /// <summary>
    /// The latest versions of this tenant's applications carrying a component the scan has linked
    /// to <paramref name="osvId"/>, plus the total for paging.
    ///
    /// <para><c>vulnerabilities</c> is the shared instance-global advisory store reached through an
    /// FK; the tenant filter sits on <c>sbom_components</c>, the only row in the join that carries
    /// one, so an advisory another tenant's application ships contributes nothing here.</para>
    /// </summary>
    public async Task<BlastRadiusPage> ListByAdvisoryAsync(
        string orgId, string osvId, int limit, int offset, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var parameters = new { orgId, osvId, limit, offset };
        var totals = await conn.QuerySingleAsync<BlastRadiusTotalsRow>(new CommandDefinition(
            """
            SELECT COUNT(*) AS RowTotal, COUNT(DISTINCT pv.project_id) AS ProjectTotal
            FROM sbom_component_vulns scv
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            JOIN sbom_components c ON c.id = scv.component_id
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            WHERE c.org_id = @orgId AND v.osv_id = @osvId AND pv.is_latest = 1
            """,
            parameters, cancellationToken: ct));

        var rows = await conn.QueryAsync<BlastRadiusRow>(new CommandDefinition(
            """
            SELECT p.id             AS ProjectId,
                   p.name           AS ProjectName,
                   p.classifier     AS Classifier,
                   pv.id            AS ProjectVersionId,
                   pv.version       AS ProjectVersion,
                   pv.policy_status AS PolicyStatus,
                   c.version        AS ComponentVersion,
                   c.purl           AS ComponentPurl,
                   c.dependency_scope AS DependencyScope
            FROM sbom_component_vulns scv
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            JOIN sbom_components c ON c.id = scv.component_id
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            JOIN projects p ON p.id = pv.project_id AND p.org_id = pv.org_id
            WHERE c.org_id = @orgId AND v.osv_id = @osvId AND pv.is_latest = 1
            ORDER BY p.name, pv.version, c.id
            LIMIT @limit OFFSET @offset
            """,
            parameters, cancellationToken: ct));
        return new BlastRadiusPage(rows.ToList(), totals.RowTotal, totals.ProjectTotal);
    }

    /// <summary>
    /// How many distinct applications ship each of <paramref name="osvIds"/>, for a table that
    /// renders one blast-radius cell per advisory row. One statement per page, never one per row.
    /// Advisories nobody ships are simply absent from the map — the caller renders a zero.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, int>> CountProjectsByAdvisoryAsync(
        string orgId, IReadOnlyList<string> osvIds, CancellationToken ct = default)
    {
        if (osvIds.Count == 0)
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        await using var conn = await _db.OpenAsync(ct);
        // IN (...) is built and parameterized in C#, not via Dapper's IN @osvIds auto-expansion —
        // Dapper binds the whole list as a single array parameter on Npgsql, which IN never accepts.
        var (keysClause, parameters) = DapperInClause.Expand("osv", osvIds);
        parameters.Add("orgId", orgId);
        // rawsql: keysClause is a parameterized IN (@osv0, @osv1, …) list built in C#, not user text.
        var rows = await conn.QueryAsync<CountRow>(new CommandDefinition(
            """
            SELECT v.osv_id AS Key, COUNT(DISTINCT pv.project_id) AS Count
            FROM sbom_component_vulns scv
            JOIN vulnerabilities v ON v.id = scv.vuln_id
            JOIN sbom_components c ON c.id = scv.component_id
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            WHERE c.org_id = @orgId AND pv.is_latest = 1 AND v.osv_id IN
            """ + " " + keysClause + " GROUP BY v.osv_id",
            parameters, cancellationToken: ct));
        return rows.ToDictionary(r => r.Key, r => r.Count, StringComparer.Ordinal);
    }

    /// <summary>
    /// How many distinct applications ship each of <paramref name="coordinates"/>, keyed by
    /// <c>{ecosystem}/{purl_name}</c>. Feeds the "N applications ship this" count on the package
    /// detail page and on each quarantine row.
    ///
    /// <para>The ecosystem and name lists are bound separately and the exact pairs are re-selected
    /// in C#: two <c>IN</c> lists over the leading columns of
    /// <c>idx_sbom_components_org_eco_name</c> is a lookup that index answers, where the
    /// concatenated <c>ecosystem || '/' || purl_name</c> key it would take to express the pairs in
    /// one predicate is an expression no index covers.</para>
    /// </summary>
    public async Task<IReadOnlyDictionary<string, int>> CountProjectsByCoordinateAsync(
        string orgId, IReadOnlyList<RegistryCoordinate> coordinates, CancellationToken ct = default)
    {
        if (coordinates.Count == 0)
        {
            return new Dictionary<string, int>(StringComparer.Ordinal);
        }

        var ecosystems = coordinates.Select(c => c.Ecosystem).Distinct(StringComparer.Ordinal).ToList();
        var names = coordinates.Select(c => c.Name).Distinct(StringComparer.Ordinal).ToList();
        var wanted = coordinates
            .Select(c => c.Key)
            .ToHashSet(StringComparer.Ordinal);

        await using var conn = await _db.OpenAsync(ct);
        var (ecoClause, parameters) = DapperInClause.Expand("eco", ecosystems);
        var (nameClause, nameParameters) = DapperInClause.Expand("nm", names);
        parameters.AddDynamicParams(nameParameters);
        parameters.Add("orgId", orgId);
        // rawsql: both clauses are parameterized IN (@eco0, …) / (@nm0, …) lists built in C#.
        var rows = await conn.QueryAsync<CoordinateCountRow>(new CommandDefinition(
            """
            SELECT c.ecosystem AS Ecosystem, c.purl_name AS Name, COUNT(DISTINCT pv.project_id) AS Count
            FROM sbom_components c
            JOIN project_versions pv ON pv.id = c.project_version_id AND pv.org_id = c.org_id
            WHERE c.org_id = @orgId AND pv.is_latest = 1 AND c.ecosystem IN
            """
            + " " + ecoClause + " AND c.purl_name IN " + nameClause
            + " GROUP BY c.ecosystem, c.purl_name",
            parameters, cancellationToken: ct));

        // The two IN lists match the cross product of the requested ecosystems and names, which is
        // a superset of the requested pairs. Narrowing back to the pairs the caller actually asked
        // for is what keeps a coordinate that only exists under another ecosystem from reporting a
        // count that belongs to a different package.
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            string key = RegistryCoordinate.KeyFor(row.Ecosystem, row.Name);
            if (wanted.Contains(key))
            {
                counts[key] = row.Count;
            }
        }

        return counts;
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class BlastRadiusTotalsRow
    {
        public int RowTotal { get; set; }
        public int ProjectTotal { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class CountRow
    {
        public string Key { get; set; } = "";
        public int Count { get; set; }
    }

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class CoordinateCountRow
    {
        public string Ecosystem { get; set; } = "";
        public string Name { get; set; } = "";
        public int Count { get; set; }
    }
}

/// <summary>
/// One page of affected applications, carrying BOTH totals.
///
/// <para>The two are different questions and a caller headlines the second.
/// <see cref="RowTotal"/> counts matching component rows and is what paginates; one application
/// listing a coordinate twice contributes two rows. <see cref="ProjectTotal"/> is the number this
/// page's summary states — distinct applications, counted across the whole result, not across the
/// page that was returned. Deriving it from <see cref="Items"/> would cap it at the page limit,
/// so an operator with sixty affected applications would read "25 applications ship this" and
/// under-scope the decision they are about to take. It is the same failure the counts endpoint
/// refuses a batch to avoid: a number on a security surface that reads as safer than reality.</para>
/// </summary>
public sealed record BlastRadiusPage(
    IReadOnlyList<BlastRadiusRow> Items,
    int RowTotal,
    int ProjectTotal);

/// <summary>One registry coordinate a blast-radius count is asked for.</summary>
public sealed record RegistryCoordinate(string Ecosystem, string Name)
{
    /// <summary>The <c>{ecosystem}/{name}</c> spelling callers key the returned map by.</summary>
    public string Key => KeyFor(Ecosystem, Name);

    /// <summary>One helper so the map's key and the caller's lookup cannot drift apart.</summary>
    public static string KeyFor(string ecosystem, string name) => ecosystem + "/" + name;
}

/// <summary>One application version shipping the coordinate or advisory that was asked about.</summary>
public sealed class BlastRadiusRow
{
    public string ProjectId { get; set; } = "";
    public string ProjectName { get; set; } = "";
    public string? Classifier { get; set; }
    public string ProjectVersionId { get; set; } = "";
    public string ProjectVersion { get; set; } = "";
    public string? PolicyStatus { get; set; }
    /// <summary>The version of the component this application ships, which need not be the one asked about.</summary>
    public string? ComponentVersion { get; set; }
    public string? ComponentPurl { get; set; }
    public string DependencyScope { get; set; } = "unknown";
}
