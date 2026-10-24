using Dapper;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// The image a scan result describes: a hosted <c>package_versions</c> row or a proxied
/// <c>cache_artifact</c> row. Every OCI scan table stores it as the repo's two-column owner,
/// <c>package_version_id</c> / <c>cache_artifact_id</c> plus <c>owner_kind</c>.
/// </summary>
public sealed record OciScanOwner(string Kind, string Id)
{
    public const string PackageVersion = "package_version";
    public const string CacheArtifact = "cache_artifact";

    public static OciScanOwner Hosted(string packageVersionId) => new(PackageVersion, packageVersionId);

    public static OciScanOwner Proxied(string cacheArtifactId) => new(CacheArtifact, cacheArtifactId);

    public bool IsHosted => Kind == PackageVersion;

    /// <summary>The <c>package_version_id</c> column value: the id for a hosted image, else null.</summary>
    public string? PackageVersionId => IsHosted ? Id : null;

    /// <summary>The <c>cache_artifact_id</c> column value: the id for a proxied image, else null.</summary>
    public string? CacheArtifactId => IsHosted ? null : Id;
}

/// <summary>A job the caller has leased.</summary>
public sealed record OciScanJob(
    string Id,
    string OrgId,
    OciScanOwner Owner,
    string Repository,
    string Digest,
    string Kind,
    int Attempts,
    string LeaseExpiresAt,
    int Deferrals = 0,
    string? CreatedAt = null,
    string? FirstDeferredAt = null)
{
    /// <summary>Claims that count against the attempt budget: every claim except a deferral.</summary>
    public int AttemptsUsed => Attempts - Deferrals;
}

/// <summary>
/// One org's scan facts for one image, read to derive the image's version status. A row exists
/// only for an image the org's scanner has posted a result for. <c>MatchedAt</c> is the oldest
/// last OSV match across the image's platforms: how stale its findings may be.
/// </summary>
public sealed record OciScanFacts(int GapCount, int AdvisoryCount, double? MaxScore, string? MatchedAt = null);

/// <summary>One advisory a scan matched against an image's inventory, as lookup reports it.</summary>
[method: ExplicitConstructor]
public sealed record OciLookupAdvisory(
    string OsvId, string? AliasesJson, string? Summary, string? Severity, double? CvssScore);

/// <summary>
/// An org's stored scan result for one image: the coverage gaps across its platforms and the
/// distinct advisories its components matched. Exists only for an image the org's scanner posted
/// a result for. <c>MatchedAt</c> is the oldest last OSV match across its platforms.
/// </summary>
public sealed record OciLookupScan(int GapCount, IReadOnlyList<OciLookupAdvisory> Advisories, string? MatchedAt = null);

/// <summary>
/// The OCI scan queue, scanner liveness and per-tenant scan facts. Every statement is keyed by
/// the caller's org: a tenant's scanner sees, leases and writes only its own org's rows.
///
/// <para>Timestamps are written and compared as fixed-width millisecond UTC strings, so lease
/// and due-time comparisons are plain text comparisons that agree on SQLite and Postgres.</para>
/// </summary>
public sealed partial class OciScanRepository
{
    private readonly IMetadataStore _db;

    public OciScanRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Queues a scan of <paramref name="owner"/> for <paramref name="orgId"/>. Returns false when
    /// the org already has a job for it: one job per (owner, org, kind), whatever its state, so a
    /// re-push, a revalidated pull or a sweep re-run queues nothing.
    /// </summary>
    public async Task<bool> EnqueueAsync(
        string orgId, OciScanOwner owner, string repository, string digest, string now, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int inserted = await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_jobs (
                id, org_id, owner_kind, package_version_id, cache_artifact_id,
                repository, digest, kind, state, attempts, created_at, updated_at)
            VALUES (
                @id, @orgId, @ownerKind, @packageVersionId, @cacheArtifactId,
                @repository, @digest, 'scan', 'pending', 0, @now, @now)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                ownerKind = owner.Kind,
                packageVersionId = owner.PackageVersionId,
                cacheArtifactId = owner.CacheArtifactId,
                repository,
                digest,
                now,
            });
        return inserted == 1;
    }

    /// <summary>
    /// Leases up to <paramref name="max"/> due jobs of <paramref name="orgId"/> until
    /// <paramref name="until"/>. Each candidate is taken by a conditional update that succeeds
    /// only while its lease is still lapsed, so two scanners claiming at once never both hold a
    /// job, on SQLite or Postgres, without <c>SKIP LOCKED</c>.
    ///
    /// <para>A job whose lease lapsed after its last allowed attempt (a scanner that crashed on
    /// it every time) is parked as failed first, so it is never claimed again.</para>
    ///
    /// <para>Only <c>scan</c> jobs are claimable unless <paramref name="includeRematch"/> is set,
    /// so a scanner that never asked for rematch jobs is never handed one. Scan jobs come first,
    /// so a newly pushed or pulled image is not queued behind a rematch backlog, and a rematch is
    /// not claimable while the same image has a scan pending: that scan replaces the inventory
    /// the rematch would read.</para>
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "An IN list built by DapperInClause.Expand: only generated @name placeholders are spliced, every "
                        + "value is bound; the rest is constant SQL text. Every statement filters on org_id.")]
    public async Task<IReadOnlyList<OciScanJob>> ClaimAsync(
        string orgId, int max, int maxAttempts, string now, string until, bool includeRematch = false,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs
            SET state = 'failed', updated_at = @now, completed_at = @now,
                last_error = 'the scanner held this job until its lease expired on every allowed attempt'
            WHERE org_id = @orgId AND state = 'pending' AND attempts - deferrals >= @maxAttempts
              AND lease_expires_at IS NOT NULL AND lease_expires_at < @now
            """,
            new { orgId, now, maxAttempts });

        var candidates = (await conn.QueryAsync<string>(
            """
            SELECT j.id FROM oci_scan_jobs j
            WHERE j.org_id = @orgId AND j.state = 'pending' AND j.attempts - j.deferrals < @maxAttempts
              AND (j.lease_expires_at IS NULL OR j.lease_expires_at < @now)
              AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= @now)
              AND (j.kind = 'scan'
                   OR (@rematch = 1 AND j.kind = 'rematch'
                       AND NOT EXISTS (
                           SELECT 1 FROM oci_scan_jobs s
                           WHERE s.org_id = @orgId AND s.kind = 'scan' AND s.state = 'pending'
                             AND s.owner_kind = j.owner_kind
                             AND (s.package_version_id = j.package_version_id
                                  OR s.cache_artifact_id = j.cache_artifact_id))))
            ORDER BY CASE WHEN j.kind = 'scan' THEN 0 ELSE 1 END, j.created_at, j.id
            LIMIT @limit
            """,
            new { orgId, now, maxAttempts, limit = max * 4, rematch = includeRematch ? 1 : 0 })).AsList();

        var claimed = new List<string>();
        foreach (string id in candidates)
        {
            if (claimed.Count == max)
            {
                break;
            }

            if (await TryLeaseAsync(conn, orgId, id, now, until))
            {
                claimed.Add(id);
            }
        }

        if (claimed.Count == 0)
        {
            return [];
        }

        var (idsClause, idsParams) = DapperInClause.Expand("id", claimed);
        idsParams.Add("orgId", orgId);
        var rows = await conn.QueryAsync<JobRow>(
            JobSelect + " WHERE org_id = @orgId AND id IN @ids".Replace("@ids", idsClause),
            idsParams);
        // In claim order: scans before rematches, then oldest first.
        var order = claimed.Select((id, i) => (id, i)).ToDictionary(x => x.id, x => x.i, StringComparer.Ordinal);
        return rows.Select(r => r.ToJob()).OrderBy(j => order[j.Id]).ToList();
    }

    /// <summary>
    /// Takes one candidate the claim listed, by a conditional update that succeeds only while the
    /// job is still pending and its lease lapsed. Another scanner may have claimed, or claimed and
    /// deferred, the same job between the listing and this update, so every condition the listing
    /// applied is checked again here.
    /// </summary>
    internal static async Task<bool> TryLeaseAsync(
        System.Data.Common.DbConnection conn, string orgId, string id, string now, string until)
    {
        return await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs
            SET lease_expires_at = @until, attempts = attempts + 1, updated_at = @now
            WHERE id = @id AND org_id = @orgId AND state = 'pending'
              AND (lease_expires_at IS NULL OR lease_expires_at < @now)
              AND (next_attempt_at IS NULL OR next_attempt_at <= @now)
            """,
            new { id, orgId, now, until }) == 1;
    }

    /// <summary>
    /// The job, when <paramref name="orgId"/> owns it, its lease is live at <paramref name="now"/>
    /// and it is still on the <paramref name="attempt"/> the caller's claim returned: a later claim
    /// bumps it, so a holder whose lease lapsed and was re-claimed no longer matches.
    /// </summary>
    public async Task<OciScanJob?> GetLeasedAsync(
        string orgId, string jobId, string now, int attempt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<JobRow>(
            JobSelect + " WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now"
            + " AND attempts = @attempt",
            new { orgId, jobId, now, attempt });
        return row?.ToJob();
    }

    /// <summary>
    /// The job, when <paramref name="orgId"/> owns it and its lease is live at <paramref name="now"/>,
    /// for the image reads (manifests and blobs), which write nothing and carry no attempt. Every
    /// route that writes takes <see cref="GetLeasedAsync"/>'s attempt fence instead.
    /// </summary>
    public async Task<OciScanJob?> GetLeasedForReadAsync(
        string orgId, string jobId, string now, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<JobRow>(
            JobSelect + " WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now",
            new { orgId, jobId, now });
        return row?.ToJob();
    }

    /// <summary>
    /// Extends a live lease to <paramref name="until"/>. False when the caller no longer holds it,
    /// including when <paramref name="attempt"/> names a claim a later one has superseded.
    /// </summary>
    public async Task<bool> ExtendLeaseAsync(
        string orgId, string jobId, string now, string until, int attempt, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs SET lease_expires_at = @until, updated_at = @now
            WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
              AND attempts = @attempt
            """,
            new { orgId, jobId, now, until, attempt }) == 1;
    }

    /// <summary>
    /// Ends the current attempt without a result. A retryable failure returns the job to pending,
    /// due at <paramref name="nextAttemptAt"/>; a final one parks it as failed. Either way nothing
    /// about the image is stamped, so it stays unscanned. False when the caller no longer holds
    /// the lease, or when <paramref name="attempt"/> is no longer the job's current claim.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "The parameter list is the call's declared inputs; a bundling type would hide which of them each "
                        + "caller supplies.")]
    public async Task<bool> FailAsync(
        string orgId, string jobId, int attempt, string now, bool park, string? nextAttemptAt, string reason,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs
            SET state = CASE WHEN @park = 1 THEN 'failed' ELSE 'pending' END,
                lease_expires_at = NULL,
                next_attempt_at = @nextAttemptAt,
                last_error = @reason,
                updated_at = @now,
                completed_at = CASE WHEN @park = 1 THEN @now ELSE NULL END
            WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
              AND attempts = @attempt
            """,
            new { orgId, jobId, attempt, now, park = park ? 1 : 0, nextAttemptAt, reason }) == 1;
    }

    /// <summary>
    /// Ends the current claim without a result because the advisory source could not be reached
    /// to verify it. The job returns to pending, due at <paramref name="nextAttemptAt"/>, and the
    /// claim is counted as a deferral, so it does not spend the attempt budget however long the
    /// outage lasts. The attempt counter itself is never wound back: it stays the claim fence.
    /// The first deferral's time is kept: the deferral window runs from it.
    /// False when the caller no longer holds the lease on <paramref name="attempt"/>.
    /// </summary>
    public async Task<bool> DeferAsync(
        string orgId, string jobId, int attempt, string now, string nextAttemptAt, string reason,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs
            SET lease_expires_at = NULL, next_attempt_at = @nextAttemptAt, last_error = @reason,
                deferrals = deferrals + 1, first_deferred_at = COALESCE(first_deferred_at, @now), updated_at = @now
            WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
              AND attempts = @attempt
            """,
            new { orgId, jobId, attempt, now, nextAttemptAt, reason }) == 1;
    }

    /// <summary>
    /// Records that <paramref name="orgId"/>'s scanner called the scan API at <paramref name="now"/>.
    /// The version and OSV fields are kept when a call does not report them.
    /// </summary>
    public async Task TouchScannerAsync(
        string orgId, string now, string? scannerVersion, string? osvSource, string? osvStateJson,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scanners (org_id, last_seen_at, scanner_version, osv_source, osv_state_json)
            VALUES (@orgId, @now, @scannerVersion, @osvSource, @osvStateJson)
            ON CONFLICT (org_id) DO UPDATE SET
                last_seen_at    = excluded.last_seen_at,
                scanner_version = COALESCE(excluded.scanner_version, oci_scanners.scanner_version),
                osv_source      = COALESCE(excluded.osv_source, oci_scanners.osv_source),
                osv_state_json  = COALESCE(excluded.osv_state_json, oci_scanners.osv_state_json)
            """,
            new { orgId, now, scannerVersion, osvSource, osvStateJson });
    }

    /// <summary>When <paramref name="orgId"/>'s scanner last called the scan API, or null if it never has.</summary>
    public async Task<string?> GetScannerLastSeenAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<string?>(
            "SELECT last_seen_at FROM oci_scanners WHERE org_id = @orgId",
            new { orgId });
    }

    /// <summary>
    /// The org's scan facts for each of the given images that has a result: total gaps across its
    /// platforms, distinct advisories across its components, and the highest CVSS score among them.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, OciScanFacts>> GetFactsAsync(
        string orgId, IReadOnlyList<string> ownerIds, CancellationToken ct = default)
    {
        if (ownerIds.Count == 0)
        {
            return new Dictionary<string, OciScanFacts>();
        }

        await using var conn = await _db.OpenAsync(ct);
        var (idsClause, idsParams) = DapperInClause.Expand("id", ownerIds);
        idsParams.Add("orgId", orgId);

        var coverage = await conn.QueryAsync<(string OwnerId, long Gaps, string? MatchedAt)>(
            """
            SELECT COALESCE(c.package_version_id, c.cache_artifact_id) AS OwnerId, SUM(c.gap_count) AS Gaps,
                   MIN(COALESCE(c.matched_at, c.scanned_at)) AS MatchedAt
            FROM oci_scan_coverage c
            WHERE c.org_id = @orgId
              AND COALESCE(c.package_version_id, c.cache_artifact_id) IN @ids
            GROUP BY COALESCE(c.package_version_id, c.cache_artifact_id)
            """.Replace("@ids", idsClause),
            idsParams);

        var advisories = (await conn.QueryAsync<(string OwnerId, long Advisories, double? MaxScore)>(
            """
            SELECT COALESCE(ic.package_version_id, ic.cache_artifact_id) AS OwnerId,
                   COUNT(DISTINCT cv.vuln_id) AS Advisories,
                   MAX(v.cvss_score) AS MaxScore
            FROM oci_component_vulns cv
            JOIN oci_image_components ic ON ic.id = cv.component_id AND ic.org_id = cv.org_id
            JOIN vulnerabilities v ON v.id = cv.vuln_id
            WHERE cv.org_id = @orgId
              AND COALESCE(ic.package_version_id, ic.cache_artifact_id) IN @ids
            GROUP BY COALESCE(ic.package_version_id, ic.cache_artifact_id)
            """.Replace("@ids", idsClause),
            idsParams)).ToDictionary(r => r.OwnerId);

        return coverage.ToDictionary(
            c => c.OwnerId,
            c => advisories.TryGetValue(c.OwnerId, out var a)
                ? new OciScanFacts((int)c.Gaps, (int)a.Advisories, a.MaxScore, c.MatchedAt)
                : new OciScanFacts((int)c.Gaps, 0, null, c.MatchedAt));
    }

    /// <summary>
    /// The org's block-gate facts for each of the given images (owner ids): whether it holds a
    /// result, the coverage gaps across its platforms, and the advisory signals the result matched,
    /// aggregated by <see cref="VulnerabilityRepository.GateAggregateColumns"/> so the OCI arms read
    /// the same projection and enrichment-freshness rules as every other ecosystem. An owner the org
    /// has no result for is absent from the answer.
    ///
    /// <para>Every statement and every join is filtered on <paramref name="orgId"/>: a proxied image
    /// is one shared row, but one tenant's scan result is never another's verdict.</para>
    /// </summary>
    /// <param name="freshCutoff">The enrichment staleness horizon, from
    /// <see cref="VulnerabilityRepository.FreshnessCutoffAsync"/>.</param>
    public async Task<IReadOnlyDictionary<string, OciGateFacts>> GetGateFactsAsync(
        string orgId, IReadOnlyList<string> ownerIds, string freshCutoff, CancellationToken ct = default)
    {
        var result = new Dictionary<string, OciGateFacts>(StringComparer.Ordinal);
        if (ownerIds.Count == 0)
        {
            return result;
        }

        await using var conn = await _db.OpenAsync(ct);
        var (idsClause, idsParams) = DapperInClause.Expand("id", ownerIds);
        idsParams.Add("orgId", orgId);
        idsParams.Add("freshCutoff", freshCutoff);

        var coverage = await conn.QueryAsync<(string OwnerId, long Gaps)>(
            """
            SELECT COALESCE(c.package_version_id, c.cache_artifact_id) AS OwnerId, SUM(c.gap_count) AS Gaps
            FROM oci_scan_coverage c
            WHERE c.org_id = @orgId
              AND COALESCE(c.package_version_id, c.cache_artifact_id) IN @ids
            GROUP BY COALESCE(c.package_version_id, c.cache_artifact_id)
            """.Replace("@ids", idsClause),
            idsParams);

        // rawsql: GateAggregateColumns is a compile-time constant; every value is a bound parameter.
        const string signalsSql = "SELECT COALESCE(ic.package_version_id, ic.cache_artifact_id) AS OwnerId, "
            + VulnerabilityRepository.GateAggregateColumns + "\n" + """
            FROM oci_component_vulns cv
            JOIN oci_image_components ic ON ic.id = cv.component_id AND ic.org_id = @orgId
            JOIN vulnerabilities v ON v.id = cv.vuln_id
            WHERE cv.org_id = @orgId
              AND COALESCE(ic.package_version_id, ic.cache_artifact_id) IN @ids
            GROUP BY COALESCE(ic.package_version_id, ic.cache_artifact_id)
            """;
        // The OCI plane carries no still-live-malicious signal, so that aggregate is a constant 0.
        var signals = (await conn.QueryAsync<VulnerabilityRepository.GateAggregateRow>(
                signalsSql.Replace("@ids", idsClause).Replace(VulnerabilityRepository.MalStillLivePlaceholder, "0"),
                idsParams))
            .ToDictionary(r => r.OwnerId, VulnerabilityRepository.ToGateSignals, StringComparer.Ordinal);

        // The advisory ids a malicious or KEV refusal names in its detail, read in the same pass so
        // the refusal never needs a second, shared-plane lookup.
        var notable = (await conn.QueryAsync<(string OwnerId, string OsvId, long Malicious, long Kev)>(
            """
            SELECT DISTINCT COALESCE(ic.package_version_id, ic.cache_artifact_id) AS OwnerId, v.osv_id AS OsvId,
                   CAST(CASE WHEN v.osv_id LIKE 'MAL-%' THEN 1 ELSE 0 END AS BIGINT) AS Malicious,
                   CAST(CASE WHEN v.is_kev = 1 THEN 1 ELSE 0 END AS BIGINT) AS Kev
            FROM oci_component_vulns cv
            JOIN oci_image_components ic ON ic.id = cv.component_id AND ic.org_id = @orgId
            JOIN vulnerabilities v ON v.id = cv.vuln_id
            WHERE cv.org_id = @orgId
              AND COALESCE(ic.package_version_id, ic.cache_artifact_id) IN @ids
              AND (v.osv_id LIKE 'MAL-%' OR v.is_kev = 1)
            """.Replace("@ids", idsClause),
            idsParams)).AsList();

        foreach (var (ownerId, gaps) in coverage)
        {
            var owned = notable.Where(n => n.OwnerId == ownerId).ToList();
            result[ownerId] = new OciGateFacts(
                HasResult: true,
                GapCount: (int)gaps,
                Signals: signals.TryGetValue(ownerId, out var s) ? s : new VulnGateSignals(VulnFacts.None))
            {
                MaliciousOsvIds = owned.Where(n => n.Malicious == 1).Select(n => n.OsvId).Order(StringComparer.Ordinal).ToList(),
                KevOsvIds = owned.Where(n => n.Kev == 1).Select(n => n.OsvId).Order(StringComparer.Ordinal).ToList(),
            };
        }

        return result;
    }

    /// <summary>
    /// For each of the given OCI packages, the org's scan facts for every image it holds: its
    /// hosted versions plus the proxied manifests it has pulled, minus a proxied manifest an
    /// uploaded version of the same digest shadows (the version page lists neither twice). An
    /// entry is null for a held image the org has no result for. Packages are read as one batch
    /// and their images' facts in fixed-size chunks, so a page costs a constant number of queries.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, IReadOnlyList<OciScanFacts?>>> GetHeldImageFactsAsync(
        string orgId, IReadOnlyList<string> packageIds, CancellationToken ct = default)
    {
        var result = new Dictionary<string, IReadOnlyList<OciScanFacts?>>();
        if (packageIds.Count == 0)
        {
            return result;
        }

        List<(string PackageId, string OwnerId)> held;
        await using (var conn = await _db.OpenAsync(ct))
        {
            var (idsClause, idsParams) = DapperInClause.Expand("pkgId", packageIds);
            idsParams.Add("orgId", orgId);
            held = (await conn.QueryAsync<(string PackageId, string OwnerId)>(
                """
                SELECT p.id AS PackageId, pv.id AS OwnerId
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.id IN @ids
                UNION ALL
                SELECT p.id AS PackageId, ca.id AS OwnerId
                FROM packages p
                JOIN cache_artifact ca
                  ON ca.ecosystem = 'oci' AND ca.filename = 'manifest' AND ca.name = p.purl_name
                JOIN tenant_artifact_access taa
                  ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
                WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.id IN @ids
                  AND NOT EXISTS (
                      SELECT 1 FROM package_versions pu
                      WHERE pu.package_id = p.id AND pu.version = ca.version)
                """.Replace("@ids", idsClause),
                idsParams)).AsList();
        }

        var facts = new Dictionary<string, OciScanFacts>();
        foreach (string[] chunk in held.Select(h => h.OwnerId).Distinct().Chunk(FactsChunkSize))
        {
            foreach (var (ownerId, f) in await GetFactsAsync(orgId, chunk, ct))
            {
                facts[ownerId] = f;
            }
        }

        foreach (var group in held.GroupBy(h => h.PackageId))
        {
            result[group.Key] = group.Select(h => facts.GetValueOrDefault(h.OwnerId)).ToList();
        }

        return result;
    }

    private const int FactsChunkSize = 500;

    /// <summary>
    /// Of the given owners (images that list <paramref name="manifestDigest"/> as a platform), the
    /// ones whose stored result for this org does NOT cover that platform: every coverage row has
    /// its manifest digest recorded and none is this one, so the scanner skipped the platform. An
    /// owner with any legacy NULL row is left to the reference graph and counts as covering it; an
    /// <see cref="UnreadableMapDigest"/> row is a recorded answer and never covers.
    /// A platform the index does not list carries <see cref="UnlistedPlatformDigest"/>, which is a
    /// recorded answer and never covers.
    /// </summary>
    public async Task<IReadOnlySet<string>> GetOwnersNotCoveringAsync(
        string orgId, IReadOnlyList<string> ownerIds, string manifestDigest, CancellationToken ct = default)
    {
        if (ownerIds.Count == 0)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        await using var conn = await _db.OpenAsync(ct);
        var (idsClause, idsParams) = DapperInClause.Expand("id", ownerIds);
        idsParams.Add("orgId", orgId);
        idsParams.Add("manifestDigest", manifestDigest);
        var rows = await conn.QueryAsync<(string OwnerId, long Unfilled, long Matching)>(
            """
            SELECT COALESCE(c.package_version_id, c.cache_artifact_id) AS OwnerId,
                   SUM(CASE WHEN c.manifest_digest IS NULL THEN 1 ELSE 0 END) AS Unfilled,
                   SUM(CASE WHEN c.manifest_digest = @manifestDigest THEN 1 ELSE 0 END) AS Matching
            FROM oci_scan_coverage c
            WHERE c.org_id = @orgId
              AND COALESCE(c.package_version_id, c.cache_artifact_id) IN @ids
            GROUP BY COALESCE(c.package_version_id, c.cache_artifact_id)
            """.Replace("@ids", idsClause),
            idsParams);
        return rows.Where(r => r.Unfilled == 0 && r.Matching == 0).Select(r => r.OwnerId).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// Recorded in <c>oci_scan_coverage.manifest_digest</c> for a platform the owning index does
    /// not list. It matches no manifest digest, and unlike NULL it is not "not yet recorded", so
    /// the row never counts as covering a platform pull.
    /// </summary>
    public const string UnlistedPlatformDigest = "unlisted";

    /// <summary>
    /// Recorded in <c>oci_scan_coverage.manifest_digest</c> when the owning image's manifest could
    /// not be read to map its platforms. Like <see cref="UnlistedPlatformDigest"/> it never covers a
    /// platform pull, so an unreadable map refuses rather than waves through; NULL is reserved for
    /// legacy rows. The sweep's backfill retries these rows until the manifest is readable.
    /// </summary>
    public const string UnreadableMapDigest = "unknown";

    /// <summary>
    /// Up to <paramref name="limit"/> images of the org whose coverage rows were written before
    /// <c>manifest_digest</c> existed, with the image's own digest, for the sweep's backfill. Keyset
    /// paged on the owner id (<paramref name="afterOwnerId"/>), so an image whose rows cannot be
    /// filled yet does not keep being re-selected ahead of the ones behind it.
    /// </summary>
    public async Task<IReadOnlyList<(OciScanOwner Owner, string Digest)>> ListCoverageMissingManifestDigestAsync(
        string orgId, int limit, string? afterOwnerId = null, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string OwnerKind, string OwnerId, string Digest)>(
            """
            SELECT DISTINCT c.owner_kind AS OwnerKind, COALESCE(c.package_version_id, c.cache_artifact_id) AS OwnerId,
                   COALESCE(pv.version, ca.version) AS Digest
            FROM oci_scan_coverage c
            LEFT JOIN package_versions pv ON pv.id = c.package_version_id
            LEFT JOIN cache_artifact ca ON ca.id = c.cache_artifact_id
            WHERE c.org_id = @orgId AND (c.manifest_digest IS NULL OR c.manifest_digest = 'unknown')
              AND COALESCE(c.package_version_id, c.cache_artifact_id) > @after
            ORDER BY OwnerId
            LIMIT @limit
            """,
            new { orgId, limit, after = afterOwnerId ?? string.Empty });
        return rows.Where(r => r.Digest is not null)
            .Select(r => (new OciScanOwner(r.OwnerKind, r.OwnerId), r.Digest)).ToList();
    }

    /// <summary>Fills the manifest digest of the owner's unfilled coverage rows from its platform map.</summary>
    public async Task<int> FillCoverageManifestDigestsAsync(
        string orgId, OciScanOwner owner, OciPlatformMap map, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var platforms = await conn.QueryAsync<(string Id, string Platform)>(
            """
            SELECT c.id AS Id, c.platform AS Platform FROM oci_scan_coverage c
            WHERE c.org_id = @orgId AND (c.manifest_digest IS NULL OR c.manifest_digest = 'unknown') AND {coverageOwner}
            """.Replace("{coverageOwner}", owner.IsHosted ? HostedCoverage : ProxiedCoverage),
            new { orgId, ownerId = owner.Id });
        int filled = 0;
        foreach (var (id, platform) in platforms)
        {
            string digest = map.ManifestDigestFor(platform) ?? UnlistedPlatformDigest;
            filled += await conn.ExecuteAsync(
                "UPDATE oci_scan_coverage SET manifest_digest = @digest WHERE org_id = @orgId AND id = @id AND (manifest_digest IS NULL OR manifest_digest = 'unknown')",
                new { orgId, id, digest });
        }

        return filled;
    }

    /// <summary>
    /// Marks the owner's legacy (NULL) coverage rows as <see cref="UnreadableMapDigest"/>, for a
    /// backfill that found the owner's manifest bytes unreadable: a NULL row counts as covering
    /// every platform, which an image whose map cannot be read must not keep claiming.
    /// </summary>
    public async Task<int> MarkCoverageManifestUnreadableAsync(
        string orgId, OciScanOwner owner, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            """
            UPDATE oci_scan_coverage SET manifest_digest = @unknown
            WHERE org_id = @orgId AND id IN (
                SELECT c.id FROM oci_scan_coverage c
                WHERE c.org_id = @orgId AND c.manifest_digest IS NULL AND {coverageOwner})
            """.Replace("{coverageOwner}", owner.IsHosted ? HostedCoverage : ProxiedCoverage),
            new { orgId, ownerId = owner.Id, unknown = UnreadableMapDigest });
    }

    /// <summary>
    /// The org's tags in <paramref name="repository"/> holding <paramref name="digest"/> as their
    /// pending digest: observed upstream, not yet promoted. Oldest hold first.
    /// </summary>
    public async Task<IReadOnlyList<OciPendingHoldView>> GetPendingHoldsAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Tag, string Digest, string? Since)>(
            """
            SELECT tag AS Tag, digest AS Digest, pending_first_seen_at AS Since
            FROM oci_tags
            WHERE org_id = @orgId AND repository = @repository AND pending_digest = @digest
            ORDER BY pending_first_seen_at, tag
            """,
            new { orgId, repository, digest });
        return rows.Select(r => new OciPendingHoldView(r.Tag, r.Digest, r.Since ?? "")).ToList();
    }

    /// <summary>
    /// When the org's oldest still-pending tag hold began, or null when no tag is holding a
    /// pending digest. Feeds the <c>dependably.oci.tag_pending_hold_age</c> gauge.
    /// </summary>
    public async Task<string?> GetOldestPendingHoldAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT MIN(pending_first_seen_at) FROM oci_tags WHERE org_id = @orgId AND pending_digest IS NOT NULL",
            new { orgId });
    }

    /// <summary>
    /// The org's own scan result for the image <paramref name="repository"/>@<paramref name="digest"/>,
    /// whether the org hosts it or has pulled it through the proxy, or null when the org has no
    /// stored result for it. Every statement is keyed by <paramref name="orgId"/>: a proxied image
    /// row is shared by every tenant that pulled it, but one tenant's result is never another's.
    ///
    /// <para>Owner rule: resolution by result. It walks the hosted owner, then the proxied one,
    /// and answers from the first that has a result, because a lookup answers "what does this org
    /// know about this digest". The version page resolves by existence instead
    /// (<see cref="ResolveImageOwnerAsync"/>); the two rules are deliberately separate.</para>
    /// </summary>
    public async Task<OciLookupScan?> FindLookupScanAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var owners = (await conn.QueryAsync<string>(
            """
            SELECT pv.id
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.name = @repository AND pv.version = @digest
            UNION ALL
            SELECT ca.id
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.filename = 'manifest'
              AND ca.name = @repository AND ca.version = @digest
            """,
            new { orgId, repository, digest })).ToList();

        foreach (string ownerId in owners)
        {
            var (platforms, gaps, matchedAt) = await conn.QuerySingleAsync<(long Platforms, long Gaps, string? MatchedAt)>(
                """
                SELECT COUNT(*) AS Platforms, COALESCE(SUM(c.gap_count), 0) AS Gaps,
                       MIN(COALESCE(c.matched_at, c.scanned_at)) AS MatchedAt
                FROM oci_scan_coverage c
                WHERE c.org_id = @orgId
                  AND COALESCE(c.package_version_id, c.cache_artifact_id) = @ownerId
                """,
                new { orgId, ownerId });
            if (platforms == 0)
            {
                continue;
            }

            var advisories = await conn.QueryAsync<OciLookupAdvisory>(
                """
                SELECT DISTINCT v.osv_id AS OsvId, v.aliases AS AliasesJson, v.summary AS Summary,
                       v.severity AS Severity, v.cvss_score AS CvssScore
                FROM oci_component_vulns cv
                JOIN oci_image_components ic ON ic.id = cv.component_id AND ic.org_id = cv.org_id
                JOIN vulnerabilities v ON v.id = cv.vuln_id
                WHERE cv.org_id = @orgId
                  AND COALESCE(ic.package_version_id, ic.cache_artifact_id) = @ownerId
                """,
                new { orgId, ownerId });
            return new OciLookupScan((int)gaps, advisories.AsList(), matchedAt);
        }

        return null;
    }

    /// <summary>
    /// The image <paramref name="repository"/>@<paramref name="digest"/> as the version page shows
    /// it to <paramref name="orgId"/>, or null when the org can see no such image.
    ///
    /// <para>Owner rule: resolution by existence, matching the version row's status badge. The
    /// org's hosted <c>package_versions</c> row wins whenever it exists, with or without a result,
    /// because the package page lists the hosted row and drops a proxied row for the same
    /// version; only without one is the proxied manifest the org reached through
    /// <c>tenant_artifact_access</c> the owner. <see cref="FindLookupScanAsync"/> resolves by
    /// result instead and is deliberately separate.</para>
    /// </summary>
    public async Task<OciScanOwner?> ResolveImageOwnerAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: the hosted half of a deliberate two-statement read; the proxy plane is the cache_artifact/tenant_artifact_access query below, consulted only when no hosted row exists.
        string? hosted = await conn.QueryFirstOrDefaultAsync<string?>(
            """
            SELECT pv.id
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci' AND p.purl_name = @repository AND pv.version = @digest
            ORDER BY pv.id
            """,
            new { orgId, repository, digest });
        if (hosted is not null)
        {
            return OciScanOwner.Hosted(hosted);
        }

        string? proxied = await conn.QueryFirstOrDefaultAsync<string?>(
            """
            SELECT ca.id
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.filename = 'manifest'
              AND ca.name = @repository AND ca.version = @digest
            ORDER BY ca.id
            """,
            new { orgId, repository, digest });
        return proxied is null ? null : OciScanOwner.Proxied(proxied);
    }

    /// <summary>
    /// Every platform row of the org's stored result for <paramref name="owner"/>, in platform
    /// order, with each platform's component and affected-component counts. Empty when the org
    /// has no result for the image.
    /// </summary>
    public async Task<IReadOnlyList<OciScanPlatformRow>> GetPlatformsAsync(
        string orgId, OciScanOwner owner, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = (await conn.QueryAsync<OciScanPlatformRow>(
            """
            SELECT c.platform AS Platform, c.scanned_at AS ScannedAt, c.scanner_version AS ScannerVersion,
                   c.extraction_version AS ExtractionVersion, c.osv_source AS OsvSource,
                   c.entrypoint_kind AS EntrypointKind, c.closure_bounded AS ClosureBounded,
                   c.gaps_json AS GapsJson, COALESCE(c.matched_at, c.scanned_at) AS MatchedAt
            FROM oci_scan_coverage c
            WHERE c.org_id = @orgId AND {coverageOwner}
            ORDER BY c.platform
            """.Replace("{coverageOwner}", owner.IsHosted ? HostedCoverage : ProxiedCoverage),
            new { orgId, ownerId = owner.Id })).AsList();
        if (rows.Count == 0)
        {
            return rows;
        }

        var counts = (await conn.QueryAsync<(string Platform, long Components, long Affected)>(
            """
            SELECT ic.platform AS Platform, COUNT(*) AS Components,
                   SUM(CASE WHEN EXISTS (
                           SELECT 1 FROM oci_component_vulns cv
                           WHERE cv.org_id = @orgId AND cv.component_id = ic.id)
                       THEN 1 ELSE 0 END) AS Affected
            FROM oci_image_components ic
            WHERE ic.org_id = @orgId AND {componentOwner}
            GROUP BY ic.platform
            """.Replace("{componentOwner}", owner.IsHosted ? HostedComponents : ProxiedComponents),
            new { orgId, ownerId = owner.Id })).ToDictionary(r => r.Platform);
        foreach (var row in rows)
        {
            if (counts.TryGetValue(row.Platform, out var c))
            {
                row.ComponentCount = c.Components;
                row.AffectedComponentCount = c.Affected;
            }
        }

        return rows;
    }

    /// <summary>
    /// The state and attempt count of the org's scan job for <paramref name="owner"/>, or null
    /// when the org has none. The job's error text is never read here.
    /// </summary>
    public async Task<(string State, int Attempts)?> GetScanJobStateAsync(
        string orgId, OciScanOwner owner, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QueryFirstOrDefaultAsync<JobStateRow>(
            """
            SELECT j.state AS State, j.attempts - j.deferrals AS Attempts
            FROM oci_scan_jobs j
            WHERE j.org_id = @orgId AND j.kind = 'scan' AND {jobOwner}
            """.Replace("{jobOwner}", owner.IsHosted ? HostedJob : ProxiedJob),
            new { orgId, ownerId = owner.Id });
        return row is null ? null : (row.State, (int)row.Attempts);
    }

    /// <summary>
    /// One page of the components the org's result holds for <paramref name="owner"/> on
    /// <paramref name="platform"/>, affected first (by worst finding: severity, then
    /// reachability), then by layer index and name, with the filter's total. With
    /// <paramref name="affectedOnly"/> only components carrying at least one finding are listed.
    /// </summary>
    public async Task<(IReadOnlyList<OciScanComponentRow> Items, int Total)> GetComponentPageAsync(
        string orgId, OciScanOwner owner, string platform, bool affectedOnly, int offset, int limit,
        CancellationToken ct = default)
    {
        string componentOwner = owner.IsHosted ? HostedComponents : ProxiedComponents;
        var args = new { orgId, ownerId = owner.Id, platform, affectedOnly = affectedOnly ? 1 : 0, offset, limit };
        await using var conn = await _db.OpenAsync(ct);
        long total = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*)
            FROM oci_image_components ic
            WHERE ic.org_id = @orgId AND {componentOwner} AND ic.platform = @platform
              AND (@affectedOnly = 0 OR EXISTS (
                  SELECT 1 FROM oci_component_vulns cv WHERE cv.org_id = @orgId AND cv.component_id = ic.id))
            """.Replace("{componentOwner}", componentOwner),
            args);

        var items = (await conn.QueryAsync<OciScanComponentRow>(
            """
            WITH worst AS (
                SELECT cv.component_id AS component_id, MIN({findingRank}) AS worst_rank,
                       COUNT(*) AS finding_count
                FROM oci_component_vulns cv
                JOIN oci_image_components ic ON ic.id = cv.component_id AND ic.org_id = cv.org_id
                JOIN vulnerabilities v ON v.id = cv.vuln_id
                WHERE cv.org_id = @orgId AND ic.org_id = @orgId AND {componentOwner} AND ic.platform = @platform
                GROUP BY cv.component_id
            )
            SELECT ic.id AS Id, ic.purl AS Purl, ic.ecosystem AS Ecosystem, ic.name AS Name,
                   ic.version AS Version, ic.source_name AS SourceName, ic.source_version AS SourceVersion,
                   ic.layer_index AS LayerIndex, ic.layer_diff_id AS LayerDiffId,
                   ic.layer_instruction AS LayerInstruction, ic.in_entrypoint_closure AS InEntrypointClosure,
                   ic.owned_by_purl AS OwnedByPurl, COALESCE(w.finding_count, 0) AS FindingCount
            FROM oci_image_components ic
            LEFT JOIN worst w ON w.component_id = ic.id
            WHERE ic.org_id = @orgId AND {componentOwner} AND ic.platform = @platform
              AND (@affectedOnly = 0 OR w.component_id IS NOT NULL)
            ORDER BY CASE WHEN w.component_id IS NULL THEN 1 ELSE 0 END, w.worst_rank,
                     CASE WHEN ic.layer_index IS NULL THEN 1 ELSE 0 END, ic.layer_index,
                     ic.name, ic.version, ic.id
            LIMIT @limit OFFSET @offset
            """.Replace("{componentOwner}", componentOwner).Replace("{findingRank}", FindingRank),
            args)).AsList();
        return (items, (int)total);
    }

    /// <summary>
    /// The findings on each of <paramref name="componentIds"/>, worst first (severity, then
    /// reachable before unknown before not observed), at most <paramref name="perComponent"/> per
    /// component, each with its advisory's details.
    /// </summary>
    public async Task<IReadOnlyList<OciScanFindingRow>> GetFindingsAsync(
        string orgId, IReadOnlyList<string> componentIds, int perComponent, CancellationToken ct = default)
    {
        if (componentIds.Count == 0)
        {
            return [];
        }

        await using var conn = await _db.OpenAsync(ct);
        var (idsClause, idsParams) = DapperInClause.Expand("id", componentIds);
        idsParams.Add("orgId", orgId);
        idsParams.Add("perComponent", perComponent);
        var rows = await conn.QueryAsync<OciScanFindingRow>(
            """
            SELECT ranked.ComponentId, ranked.OsvId, ranked.Reachability, ranked.NotObservedBasis,
                   ranked.Confidence, ranked.AliasesJson, ranked.Summary, ranked.Severity, ranked.CvssScore
            FROM (
                SELECT cv.component_id AS ComponentId, v.osv_id AS OsvId,
                       cv.reachability_status AS Reachability, cv.not_observed_basis AS NotObservedBasis,
                       cv.confidence AS Confidence, v.aliases AS AliasesJson, v.summary AS Summary,
                       v.severity AS Severity, v.cvss_score AS CvssScore,
                       ROW_NUMBER() OVER (
                           PARTITION BY cv.component_id ORDER BY {findingRank}, v.osv_id) AS rn
                FROM oci_component_vulns cv
                JOIN vulnerabilities v ON v.id = cv.vuln_id
                WHERE cv.org_id = @orgId AND cv.component_id IN @ids
            ) ranked
            WHERE ranked.rn <= @perComponent
            ORDER BY ranked.ComponentId, ranked.rn
            """.Replace("{findingRank}", FindingRank).Replace("@ids", idsClause),
            idsParams);
        return rows.AsList();
    }

    // A finding's rank, lower is worse: severity band (unscored last), then reachability.
    private const string FindingRank = """
        (CASE v.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END) * 3
        + (CASE cv.reachability_status WHEN 'reachable' THEN 0 WHEN 'not_observed' THEN 2 ELSE 1 END)
        """;

    // Owner predicates, one per owner kind, so each statement can use the partial owner indexes.
    private const string HostedCoverage = "c.owner_kind = 'package_version' AND c.package_version_id = @ownerId";
    private const string ProxiedCoverage = "c.owner_kind = 'cache_artifact' AND c.cache_artifact_id = @ownerId";
    private const string HostedComponents = "ic.owner_kind = 'package_version' AND ic.package_version_id = @ownerId";
    private const string ProxiedComponents = "ic.owner_kind = 'cache_artifact' AND ic.cache_artifact_id = @ownerId";
    private const string HostedJob = "j.owner_kind = 'package_version' AND j.package_version_id = @ownerId";
    private const string ProxiedJob = "j.owner_kind = 'cache_artifact' AND j.cache_artifact_id = @ownerId";

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    private sealed class JobStateRow
    {
        public string State { get; set; } = "";
        public long Attempts { get; set; }
    }

    /// <summary>
    /// Queues every catalogued image <paramref name="orgId"/> holds that has no scan job yet:
    /// its hosted OCI versions, and the proxied OCI manifests it has pulled. Returns the number
    /// queued.
    /// </summary>
    public async Task<int> EnqueueMissingAsync(string orgId, string now, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var missing = await conn.QueryAsync<(string OwnerKind, string OwnerId, string Repository, string Digest)>(
            """
            SELECT 'package_version' AS OwnerKind, pv.id AS OwnerId, p.name AS Repository, pv.version AS Digest
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
              AND NOT EXISTS (
                  SELECT 1 FROM oci_scan_jobs j
                  WHERE j.org_id = @orgId AND j.package_version_id = pv.id AND j.kind = 'scan')
            UNION ALL
            SELECT 'cache_artifact' AS OwnerKind, ca.id AS OwnerId, ca.name AS Repository, ca.version AS Digest
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.filename = 'manifest'
              AND NOT EXISTS (
                  SELECT 1 FROM oci_scan_jobs j
                  WHERE j.org_id = @orgId AND j.cache_artifact_id = ca.id AND j.kind = 'scan')
            LIMIT @limit
            """,
            new { orgId, limit });

        int queued = 0;
        foreach (var (ownerKind, ownerId, repository, digest) in missing)
        {
            var owner = new OciScanOwner(ownerKind, ownerId);
            if (await EnqueueAsync(orgId, owner, repository, digest, now, ct))
            {
                queued++;
            }
        }

        return queued;
    }

    /// <summary>
    /// The active orgs that have a scanner: every org whose scanner has ever called the scan API.
    /// An org that never ran one has nothing to drain its queue, so the sweep leaves it alone.
    /// The caller must hold a cross-tenant scope.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListScanningOrgsAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: the sweep's org enumeration; each org is then processed under its own scope.
        var orgs = await conn.QueryAsync<string>(
            """
            SELECT s.org_id FROM oci_scanners s
            JOIN orgs o ON o.id = s.org_id
            WHERE o.deleted_at IS NULL AND o.status = 'active'
            ORDER BY s.org_id
            """);
        return orgs.AsList();
    }

    // xtenant: a column list with no WHERE of its own; every use appends `WHERE org_id = @orgId`.
    private const string JobSelect = """
        SELECT id AS Id, org_id AS OrgId, owner_kind AS OwnerKind,
               COALESCE(package_version_id, cache_artifact_id) AS OwnerId,
               repository AS Repository, digest AS Digest, kind AS Kind,
               attempts AS Attempts, lease_expires_at AS LeaseExpiresAt,
               deferrals AS Deferrals, created_at AS CreatedAt, first_deferred_at AS FirstDeferredAt
        FROM oci_scan_jobs
        """;

    // A class with setters rather than a positional record: Dapper converts each column to the
    // property's type, which absorbs Postgres INTEGER (int) against SQLite INTEGER (long).
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    private sealed class JobRow
    {
        public string Id { get; set; } = "";
        public string OrgId { get; set; } = "";
        public string OwnerKind { get; set; } = "";
        public string OwnerId { get; set; } = "";
        public string Repository { get; set; } = "";
        public string Digest { get; set; } = "";
        public string Kind { get; set; } = "";
        public long Attempts { get; set; }
        public string? LeaseExpiresAt { get; set; }
        public long Deferrals { get; set; }
        public string? CreatedAt { get; set; }
        public string? FirstDeferredAt { get; set; }

        public OciScanJob ToJob() => new(
            Id, OrgId, new OciScanOwner(OwnerKind, OwnerId), Repository, Digest, Kind, (int)Attempts,
            LeaseExpiresAt ?? "", (int)Deferrals, CreatedAt, FirstDeferredAt);
    }
}
