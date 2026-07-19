using Dapper;

namespace Dependably.Infrastructure;

// Paginated package listing (search, sort, filter) plus its private SQL-fragment helpers. Split
// out of PackageRepository.cs (partial class) to keep any single file under the 1000-line cap;
// see that file for CRUD, construction, and the shared _db/_downloadCountWriter/_time fields.
public sealed partial class PackageRepository
{
    public async Task<(IReadOnlyList<Package> Items, int Total)> ListPaginatedAsync(
        PackageListQuery query, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Substring match, deliberately: package names carry an ecosystem-specific prefix the user
        // does not type. npm scopes ('@babel/core' is found by searching 'core'), Maven
        // groupId:artifactId coordinates (found by artifactId), and the npm and Cargo search
        // protocols this feeds all depend on matching mid-name. Anchoring the pattern to the
        // prefix would make those searches return nothing.
        //
        // The leading wildcard is therefore load-bearing, and no B-tree index can range-bound it
        // on either provider — see FullFilterClause for how the scan is bounded instead.
        string? escapedSearch = query.Search?.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        string? searchPattern = escapedSearch is not null ? $"%{escapedSearch}%" : null;

        int total = await conn.ExecuteScalarAsync<int>(CountSql,
            new { orgId = query.OrgId, ecosystem = query.Ecosystem, searchPattern });

        // Plain-column sorts (name/purl/ecosystem/created — the defaults) never depend on the
        // aggregate columns, so page the ids cheaply on the packages table first, then compute
        // the ~14 correlated aggregate subqueries only for the page's ids. This keeps a 25-row
        // page from evaluating the full projection for every package in the org before LIMIT.
        // Aggregate sorts (vulns/versions/downloads) rank on a computed column and cannot be
        // paged before it exists, so they keep the single full-CTE shape.
        string? plainOrderBy = PlainOrderByOrNull(query.SortBy, query.SortDir);
        if (plainOrderBy is not null)
        {
            // rawsql: plainOrderBy is one of PlainOrderByOrNull's fixed literal ORDER BY
            // fragments (no caller input reaches it); every value is a bound parameter.
#pragma warning disable S2077 // Query built from a whitelisted ORDER BY fragment, not user input.
            var pageIds = (await conn.QueryAsync<string>(
                PageIdSql + " " + plainOrderBy + SelectSqlSuffix,
                new { orgId = query.OrgId, ecosystem = query.Ecosystem, searchPattern, limit = query.Limit, offset = query.Offset })).ToList();
#pragma warning restore S2077

            if (pageIds.Count == 0)
            {
                return (new List<Package>(), total);
            }

            // The @pageIds token is swapped for a literal (@pageId0, @pageId1, ...) list before the
            // query reaches Dapper — see DapperInClause for why Dapper's own IN @pageIds
            // auto-expansion cannot be trusted here (it silently binds the whole list as one
            // Postgres array parameter instead, which IN never accepts).
            var (pageIdsClause, pageIdsParams) = DapperInClause.Expand("pageId", pageIds);
            pageIdsParams.Add("orgId", query.OrgId);
            var pageRows = await conn.QueryAsync<Package>(
                PageHydrateSqlFor(plainOrderBy).Replace("@pageIds", pageIdsClause),
                pageIdsParams);
            return (ApplyAbandonedState(pageRows), total);
        }

        var rows = await conn.QueryAsync<Package>(FullCteSqlFor(query.SortBy, query.SortDir),
            new { orgId = query.OrgId, ecosystem = query.Ecosystem, searchPattern, limit = query.Limit, offset = query.Offset });
        return (ApplyAbandonedState(rows), total);
    }

    // Computes the "abandoned" tri-state for each row in C# (against the injected TimeProvider)
    // rather than in SQL, so the derivation stays deterministic under frozen-clock tests and
    // provider-agnostic (no strftime/to_char branch needed).
    private List<Package> ApplyAbandonedState(IEnumerable<Package> rows)
    {
        var list = rows.ToList();
        foreach (var pkg in list)
        {
            pkg.AbandonedState = AbandonedStateOf(pkg.UpstreamLatestPublishedAt);
        }
        return list;
    }

    // Search predicate matches FullFilterClause exactly — see there for why it is LOWER()-folded,
    // substring-matched, and bounded by org/ecosystem rather than by a name index. internal so the
    // repository tests can EXPLAIN QUERY PLAN this exact string and assert the org bound still
    // holds, rather than planning a copy that can drift from what ships.
    internal const string CountSql =
        "SELECT COUNT(*) FROM packages p WHERE p.org_id = @orgId" +
        " AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)" +
        " AND (@searchPattern IS NULL OR LOWER(p.name) LIKE LOWER(@searchPattern) ESCAPE '\\')";

    // Shared CTE projection body: the SELECT ... FROM packages p that computes every aggregate
    // column for whatever set of packages the appended WHERE clause selects. The trailing WHERE,
    // the ORDER BY, and the LIMIT/OFFSET are appended by the query shapes below. Every fragment
    // is a compile-time constant — user input only ever arrives as bound @parameters.
    private const string PkgDataSelect = """
            SELECT p.id, p.org_id as OrgId, p.ecosystem, p.name, p.purl_name as PurlName,
                   p.is_proxy as IsProxy, p.created_at as CreatedAt,
                   p.same_version_push_override as SameVersionPushOverride,
                   -- Counts VERSIONS, not catalogue rows, and so must dedupe on two axes. The
                   -- cache plane is keyed UNIQUE (ecosystem, name, version, filename): one proxied
                   -- version owns one row per file, so a Maven version (jar+pom+sources+javadoc)
                   -- casts 4 rows, NuGet with its .nuspec 2, multi-file PyPI 2. A version present
                   -- on both planes casts a row on each. UNION + COUNT(DISTINCT) collapses both —
                   -- the same shape the severity counts below use — so the tile reports the version
                   -- count the detail page renders (ArtifactInventoryRepository
                   -- .ListServeableVersionsAsync, which suppresses a proxy version already
                   -- uploaded) rather than a file tally.
                   (SELECT COUNT(DISTINCT ver) FROM (
                        SELECT pv2.version AS ver FROM package_versions pv2
                        WHERE pv2.package_id = p.id AND pv2.origin = 'uploaded'
                        UNION
                        SELECT ca.version FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ) vn) as VersionCount,
                   -- Severity counts span both planes: uploaded versions carry
                   -- owner_kind='package_version' vuln rows (joined via package_version_id),
                   -- proxy versions carry owner_kind='cache_artifact' rows on the global plane
                   -- (joined via cache_artifact_id, org-scoped through tenant_artifact_access and
                   -- matched to this package by ecosystem + purl_name). UNION + COUNT(DISTINCT)
                   -- dedupes a CVE present on both planes for the same package.
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'CRITICAL'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'CRITICAL'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ) vc) as CriticalCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'HIGH'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'HIGH'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ) vc) as HighCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'MEDIUM'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'MEDIUM'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ) vc) as MediumCount,
                   (SELECT COUNT(DISTINCT vid) FROM (
                        SELECT pvv.vuln_id AS vid FROM package_versions pv2
                        JOIN package_version_vulns pvv ON pvv.package_version_id = pv2.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'LOW'
                        WHERE pv2.package_id = p.id
                        UNION
                        SELECT pvv.vuln_id FROM cache_artifact ca
                        JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                        JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                        JOIN vulnerabilities v ON v.id = pvv.vuln_id AND v.severity = 'LOW'
                        WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ) vc) as LowCount,
                   -- Sums download EVENTS, so — unlike VersionCount above — it deliberately does
                   -- not dedupe per version. Every counter it adds is an independent tally of real
                   -- fetches: the cache plane bumps download_count per (org_id, cache_artifact_id),
                   -- i.e. once per file fetched, and tenant_artifact_access is keyed on that pair,
                   -- so the join is 1:1 and fans out no row. Both planes agree on this unit — a
                   -- hosted multi-file version bumps its one row per file fetched too. Collapsing
                   -- the cache arm to one row per version would discard fetches that really
                   -- happened and would under-report against the uploaded arm.
                   (
                       SELECT COALESCE(SUM(download_count), 0) FROM package_versions
                       WHERE package_id = p.id AND origin = 'uploaded'
                   ) + COALESCE((
                       SELECT SUM(taa.download_count) FROM cache_artifact ca
                       JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                       WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                   ), 0) as TotalDownloads,
                   p.upstream_latest_version as UpstreamLatestVersion,
                   p.upstream_latest_published_at as UpstreamLatestPublishedAt,
                   (EXISTS (SELECT 1 FROM package_versions pvm
                           JOIN package_version_vulns pvv ON pvv.package_version_id = pvm.id
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE pvm.package_id = p.id
                             AND v.osv_id LIKE 'MAL-%')
                    OR EXISTS (SELECT 1 FROM cache_artifact ca
                           JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                           JOIN package_version_vulns pvv ON pvv.cache_artifact_id = ca.id
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name
                             AND v.osv_id LIKE 'MAL-%')) as HasMaliciousVersion,
                   CASE
                     WHEN p.upstream_latest_version IS NULL THEN 'unknown'
                     WHEN EXISTS (
                         SELECT 1 FROM package_versions pvl
                         WHERE pvl.package_id = p.id
                           AND pvl.version = p.upstream_latest_version
                           AND pvl.origin = 'uploaded'
                     ) OR EXISTS (
                         SELECT 1 FROM cache_artifact ca
                         JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                         WHERE taa.org_id = p.org_id
                           AND ca.ecosystem = p.ecosystem
                           AND ca.name = p.purl_name
                           AND ca.version = p.upstream_latest_version
                     ) THEN 'current'
                     ELSE 'stale'
                   END as LatestState
            FROM packages p
        """;

    private const string CteOpen = "WITH pkg_data AS (";
    private const string CteOrderTail = ") SELECT * FROM pkg_data ORDER BY ";

    // The org/ecosystem/search filter used by the full-CTE path and by CountSql. ESCAPE '\'
    // matches the wildcard-escaping ListPaginatedAsync applies to the search term.
    //
    // LOWER() on both sides is what makes the two providers agree: SQLite's LIKE folds ASCII case
    // by default, Postgres's does not, so the bare `name LIKE @searchPattern` returned different
    // rows per provider for the same search. Applying the engine's own LOWER() to the column and
    // the pattern keeps each provider self-consistent and settles both on SQLite's established
    // case-insensitive behaviour. ASCII folds identically on both engines; non-ASCII case folding
    // still differs (Postgres folds it, SQLite does not), which no supported ecosystem's naming
    // rules reach. LOWER() rather than COLLATE NOCASE: NOCASE is a SQLite-only collation name and
    // errors on Postgres.
    //
    // The search term is matched as a substring, so this predicate is not sargable on either
    // provider: a leading-wildcard LIKE cannot be range-bound by a B-tree whatever its collation
    // or opclass, and Postgres additionally cannot serve it from an index-only scan because the
    // LOWER(name) qual still requires the `name` attribute from the heap. The scan is bounded
    // instead by org (and ecosystem when supplied) through idx_packages_org_ecosystem, so the
    // name filter only ever runs across the tenant's own rows — never the whole table. Indexed
    // substring matching would need a trigram/full-text index (Postgres pg_trgm GIN, SQLite
    // FTS5), which is a schema-and-deployment change rather than an index addition.
    private const string FullFilterClause =
        " WHERE p.org_id = @orgId" +
        " AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)" +
        " AND (@searchPattern IS NULL OR LOWER(p.name) LIKE LOWER(@searchPattern) ESCAPE '\\')";

    // The page-hydrate filter: the page's ids are already resolved and org-scoped by phase 1,
    // so hydrate exactly those rows. org_id stays in the predicate as the tenancy invariant. The
    // @pageIds token is replaced with a literal (@pageId0, @pageId1, ...) list at call time — see
    // DapperInClause and ListPaginatedAsync's use of PageHydrateSqlFor.
    private const string PageFilterClause = " WHERE p.org_id = @orgId AND p.id IN @pageIds";

    private const string SelectSqlSuffix = " LIMIT @limit OFFSET @offset";

    // Phase 1 of the two-phase plain-column path: pick the page's ids from the packages table
    // alone, no aggregate subqueries. The sort-key columns are aliased to the same names the
    // full-CTE projection exposes so a single ORDER BY fragment drives both phases identically.
    // The search predicate matches FullFilterClause exactly — see there for why it is LOWER()-folded,
    // substring-matched, and bounded by org/ecosystem rather than by a name index. The two shapes
    // must agree: this phase picks the page's ids and the full-CTE path is its parity reference,
    // so a filter that differed would page a different row-set than the reference query returns.
    private const string PageIdSql = """
        SELECT p.id AS id, p.name AS name, p.purl_name AS PurlName,
               p.ecosystem AS ecosystem, p.created_at AS CreatedAt
        FROM packages p
        WHERE p.org_id = @orgId
          AND (@ecosystem IS NULL OR p.ecosystem = @ecosystem)
          AND (@searchPattern IS NULL OR LOWER(p.name) LIKE LOWER(@searchPattern) ESCAPE '\')
        ORDER BY
        """;

    // Plain-column sorts resolve to a packages-table ORDER BY with an `id` tiebreaker so the
    // phase-1 id page and the phase-2 aggregate hydrate agree on row order exactly, even when
    // the sort key ties. Aggregate sorts (vulns/versions/downloads) rank on a computed column
    // and return null → the caller takes the single full-CTE path instead.
    private static string? PlainOrderByOrNull(string sortBy, string sortDir)
    {
        bool desc = sortDir == "desc";
        return sortBy switch
        {
            "name" => (desc ? "name DESC" : "name ASC") + ", id ASC",
            "purl" => (desc ? "PurlName DESC" : "PurlName ASC") + ", id ASC",
            "ecosystem" => (desc ? "ecosystem DESC" : "ecosystem ASC") + ", id ASC",
            "vulns" or "versions" or "downloads" => null,
            _ => (desc ? "CreatedAt DESC" : "CreatedAt ASC") + ", id ASC",
        };
    }

    // Phase 2 of the two-phase plain-column path: compute the aggregate columns only for the
    // already-paged ids, re-applying the identical ORDER BY so the hydrated rows keep phase 1's
    // order. No LIMIT/OFFSET — the id set is already the page.
    private static string PageHydrateSqlFor(string plainOrderBy)
        => CteOpen + PkgDataSelect + PageFilterClause + CteOrderTail + plainOrderBy;

    // Single full-CTE query: evaluates the aggregate projection for every package matching the
    // org/ecosystem/search filter, then sorts and pages. Used for the aggregate sorts and as the
    // faithful parity reference for the plain sorts. Bounded whitelist; never composes user input.
    internal static string FullCteSqlFor(string sortBy, string sortDir)
    {
        bool desc = sortDir == "desc";
        string orderBy = sortBy switch
        {
            "name" => desc ? "name DESC" : "name ASC",
            "purl" => desc ? "PurlName DESC" : "PurlName ASC",
            "vulns" => desc
                ? "(CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) DESC"
                : "(CriticalCount * 1000 + HighCount * 100 + MediumCount * 10 + LowCount) ASC",
            "ecosystem" => desc ? "ecosystem DESC" : "ecosystem ASC",
            "versions" => desc ? "VersionCount DESC" : "VersionCount ASC",
            "downloads" => desc ? "TotalDownloads DESC" : "TotalDownloads ASC",
            _ => desc ? "CreatedAt DESC" : "CreatedAt ASC",
        };
        return CteOpen + PkgDataSelect + FullFilterClause + CteOrderTail + orderBy + SelectSqlSuffix;
    }

}
