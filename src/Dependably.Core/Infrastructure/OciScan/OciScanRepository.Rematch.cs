using System.Data.Common;
using System.Runtime.CompilerServices;
using Dapper;

namespace Dependably.Infrastructure.OciScan;

/// <summary>One platform of a stored scan result, as the inventory read serves it.</summary>
public sealed class OciInventoryPlatform
{
    /// <summary>The coverage row's id: the inventory token a match result echoes back.</summary>
    public string Id { get; set; } = "";
    public string Platform { get; set; } = "";
    public string ExtractionVersion { get; set; } = "";
    public string ScannerVersion { get; set; } = "";
    public string? ContentGapsJson { get; set; }
    public string? EntrypointKind { get; set; }
    public long ClosureBounded { get; set; }
}

/// <summary>One stored component, as the inventory read serves it.</summary>
public sealed class OciInventoryComponent
{
    public string Id { get; set; } = "";
    public string Platform { get; set; } = "";
    public string Purl { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string? SourceName { get; set; }
    public string? SourceVersion { get; set; }
}

/// <summary>An image the rematch sweep found due, and whether its stored result can be re-matched.</summary>
public sealed record OciRematchCandidate(
    OciScanOwner Owner, string Repository, string Digest, string OldestMatch, bool Legacy);

public sealed partial class OciScanRepository
{
    /// <summary>
    /// Records whether <paramref name="orgId"/>'s scanner asked for rematch jobs on its latest
    /// claim. Written on every claim, on and off, so a scanner downgrade clears it and the sweep
    /// stops queueing work the remaining scanner cannot claim.
    /// </summary>
    public async Task SetAcceptsRematchAsync(string orgId, bool accepts, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE oci_scanners SET accepts_rematch = @accepts WHERE org_id = @orgId",
            new { orgId, accepts = accepts ? 1 : 0 });
    }

    /// <summary>True when <paramref name="orgId"/>'s scanner last claimed with <c>rematch</c> among its kinds.</summary>
    public async Task<bool> AcceptsRematchAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long? accepts = await conn.QuerySingleOrDefaultAsync<long?>(
            "SELECT accepts_rematch FROM oci_scanners WHERE org_id = @orgId",
            new { orgId });
        return accepts == 1;
    }

    /// <summary>
    /// The job when <paramref name="orgId"/> owns it, in any state and whoever holds it. Lets a
    /// route tell a job that is not the org's (404) from one whose lease or attempt the caller
    /// no longer holds (409).
    /// </summary>
    public async Task<OciScanJob?> FindAsync(string orgId, string jobId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<JobRow>(
            JobSelect + " WHERE org_id = @orgId AND id = @jobId",
            new { orgId, jobId });
        return row?.ToJob();
    }

    /// <summary>
    /// Queues a fresh <paramref name="kind"/> job for an image whose job of that kind may already
    /// be finished, and returns whether this call queued it.
    ///
    /// <para>One job per (owner, org, kind) whatever its state, so a finished job is replaced
    /// rather than reset: resetting it would hand out attempt numbers its earlier run already
    /// used, and a scanner still holding one of those (its lease lapsed, and a later attempt
    /// finished the job) would pass the attempt fence against the new holder's lease. A new id
    /// refuses that scanner outright.</para>
    ///
    /// <para>The replacement is two conditional statements, so concurrent writers (the sweep, a
    /// scanner's re-extract, a push or pull enqueue) cannot both insert or delete a row another
    /// has just made pending: the delete never removes a pending job, and an insert that meets one
    /// does nothing, which is the outcome either way.</para>
    /// </summary>
    public async Task<bool> RequeueAsync(
        string orgId, OciScanOwner owner, string repository, string digest, string kind, string now,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await RequeueAsync(conn, null, orgId, owner, repository, digest, kind, now);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "The parameter list is the call's declared inputs; a bundling type would hide which of them each "
                        + "caller supplies.")]
    internal static async Task<bool> RequeueAsync(
        DbConnection conn, DbTransaction? tx, string orgId, OciScanOwner owner, string repository, string digest,
        string kind, string now)
    {
        var args = new
        {
            id = Guid.NewGuid().ToString("N"),
            orgId,
            ownerKind = owner.Kind,
            packageVersionId = owner.PackageVersionId,
            cacheArtifactId = owner.CacheArtifactId,
            repository,
            digest,
            kind,
            now,
        };
        await conn.ExecuteAsync(
            """
            DELETE FROM oci_scan_jobs
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
              AND kind = @kind AND state <> 'pending'
            """,
            args, tx);
        int inserted = await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_jobs (
                id, org_id, owner_kind, package_version_id, cache_artifact_id,
                repository, digest, kind, state, attempts, created_at, updated_at)
            VALUES (
                @id, @orgId, @ownerKind, @packageVersionId, @cacheArtifactId,
                @repository, @digest, @kind, 'pending', 0, @now, @now)
            ON CONFLICT DO NOTHING
            """,
            args, tx);
        return inserted == 1;
    }

    /// <summary>
    /// Ends a leased rematch job because the stored inventory is too old to re-match (the scanner's
    /// extractor is newer than the one that wrote it), and queues a re-extraction in its place:
    /// the rematch job closes as done and the image's scan job is replaced with a fresh pending
    /// one, in one transaction. The image keeps its previous result until the re-extraction
    /// posts. Returns <c>(false, false)</c> when the caller no longer holds the job's lease or
    /// attempt, and otherwise whether a re-extraction was queued by this call (false when one was
    /// already pending).
    /// </summary>
    public async Task<(bool Closed, bool Requeued)> ReextractAsync(OciScanJob job, string now, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        int closed = await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs
            SET state = 'done', lease_expires_at = NULL, last_error = NULL,
                updated_at = @now, completed_at = @now
            WHERE org_id = @orgId AND id = @jobId AND state = 'pending' AND lease_expires_at >= @now
              AND attempts = @attempt AND kind = 'rematch'
            """,
            new { orgId = job.OrgId, jobId = job.Id, attempt = job.Attempts, now }, tx);
        if (closed != 1)
        {
            await tx.RollbackAsync(ct);
            return (false, false);
        }

        bool requeued = await RequeueAsync(
            conn, tx, job.OrgId, job.Owner, job.Repository, job.Digest, OciScanKinds.Scan, now);
        await tx.CommitAsync(ct);
        return (true, requeued);
    }

    /// <summary>
    /// The images <paramref name="orgId"/> still holds whose oldest last match across their
    /// platforms is older than <paramref name="threshold"/>, oldest first, at most
    /// <paramref name="limit"/>. Excludes an image with a job pending of either kind, and one
    /// whose job finished at or after the threshold, so a parked job waits one age window before
    /// it is queued again. <c>Legacy</c> marks a result with a platform row that carries no
    /// content-gap classification: it cannot be re-matched without losing a gap, so it is
    /// re-extracted instead. With <paramref name="unverifiedOnly"/>, only an image with a platform
    /// whose gaps name advisories the advisory source has not yet verified is listed.
    /// </summary>
    public async Task<IReadOnlyList<OciRematchCandidate>> ListRematchDueAsync(
        string orgId, string threshold, int limit, bool unverifiedOnly = false, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<CandidateRow>(
            """
            SELECT due.OwnerKind, due.OwnerId, due.Repository, due.Digest, due.OldestMatch, due.LegacyRows
            FROM (
                SELECT 'package_version' AS OwnerKind, pv.id AS OwnerId, p.name AS Repository, pv.version AS Digest,
                       MIN(COALESCE(c.matched_at, c.scanned_at)) AS OldestMatch,
                       SUM(CASE WHEN c.content_gaps_json IS NULL THEN 1 ELSE 0 END) AS LegacyRows
                FROM oci_scan_coverage c
                JOIN package_versions pv ON pv.id = c.package_version_id
                JOIN packages p ON p.id = pv.package_id
                WHERE c.org_id = @orgId AND c.owner_kind = 'package_version'
                  AND p.org_id = @orgId AND p.ecosystem = 'oci'
                  AND NOT EXISTS (
                      SELECT 1 FROM oci_scan_jobs j
                      WHERE j.org_id = @orgId AND j.package_version_id = pv.id
                        AND (j.state = 'pending' OR j.updated_at >= @threshold))
                GROUP BY pv.id, p.name, pv.version
                HAVING MIN(COALESCE(c.matched_at, c.scanned_at)) < @threshold
                   AND (@unverifiedOnly = 0 OR SUM(CASE WHEN c.gaps_json LIKE @unverifiedGap ESCAPE '\' THEN 1 ELSE 0 END) > 0)
                UNION ALL
                SELECT 'cache_artifact' AS OwnerKind, ca.id AS OwnerId, ca.name AS Repository, ca.version AS Digest,
                       MIN(COALESCE(c.matched_at, c.scanned_at)) AS OldestMatch,
                       SUM(CASE WHEN c.content_gaps_json IS NULL THEN 1 ELSE 0 END) AS LegacyRows
                FROM oci_scan_coverage c
                JOIN cache_artifact ca ON ca.id = c.cache_artifact_id
                WHERE c.org_id = @orgId AND c.owner_kind = 'cache_artifact'
                  AND ca.ecosystem = 'oci' AND ca.filename = 'manifest'
                  AND EXISTS (
                      SELECT 1 FROM tenant_artifact_access taa
                      WHERE taa.org_id = @orgId AND taa.cache_artifact_id = ca.id)
                  AND NOT EXISTS (
                      SELECT 1 FROM oci_scan_jobs j
                      WHERE j.org_id = @orgId AND j.cache_artifact_id = ca.id
                        AND (j.state = 'pending' OR j.updated_at >= @threshold))
                GROUP BY ca.id, ca.name, ca.version
                HAVING MIN(COALESCE(c.matched_at, c.scanned_at)) < @threshold
                   AND (@unverifiedOnly = 0 OR SUM(CASE WHEN c.gaps_json LIKE @unverifiedGap ESCAPE '\' THEN 1 ELSE 0 END) > 0)
            ) due
            ORDER BY due.OldestMatch, due.OwnerId
            LIMIT @limit
            """,
            new
            {
                orgId,
                threshold,
                limit,
                unverifiedOnly = unverifiedOnly ? 1 : 0,
                unverifiedGap = LikePattern.Contains(OciScanResultWriter.UnverifiedGapMarker),
            });
        return rows
            .Select(r => new OciRematchCandidate(
                new OciScanOwner(r.OwnerKind, r.OwnerId), r.Repository, r.Digest, r.OldestMatch, r.LegacyRows > 0))
            .ToList();
    }

    /// <summary>
    /// Up to <paramref name="limit"/> images of <paramref name="orgId"/> whose scan job was parked
    /// as failed before <paramref name="threshold"/>, oldest first, that the org still holds and
    /// that have no pending job of either kind. A parked job is never claimed again, so this is how its image gets another scan: the
    /// sweep replaces the job with a fresh one (<see cref="RequeueAsync(string, OciScanOwner, string, string, string, string, CancellationToken)"/>),
    /// a new id with its own attempt budget, once per age window, like any other finished job.
    /// </summary>
    public async Task<IReadOnlyList<(OciScanOwner Owner, string Repository, string Digest)>> ListParkedScansDueAsync(
        string orgId, string threshold, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string OwnerKind, string OwnerId, string Repository, string Digest)>(
            """
            SELECT j.owner_kind AS OwnerKind, COALESCE(j.package_version_id, j.cache_artifact_id) AS OwnerId,
                   j.repository AS Repository, j.digest AS Digest
            FROM oci_scan_jobs j
            WHERE j.org_id = @orgId AND j.kind = 'scan' AND j.state = 'failed' AND j.updated_at < @threshold
              AND (
                  (j.owner_kind = 'package_version' AND EXISTS (
                      SELECT 1 FROM package_versions pv
                      JOIN packages pk ON pk.id = pv.package_id
                      WHERE pv.id = j.package_version_id AND pk.org_id = @orgId))
                  OR
                  (j.owner_kind = 'cache_artifact' AND EXISTS (
                      SELECT 1 FROM tenant_artifact_access taa
                      WHERE taa.org_id = @orgId AND taa.cache_artifact_id = j.cache_artifact_id)))
              AND NOT EXISTS (
                  SELECT 1 FROM oci_scan_jobs p
                  WHERE p.org_id = @orgId AND p.state = 'pending' AND p.owner_kind = j.owner_kind
                    AND (p.package_version_id = j.package_version_id OR p.cache_artifact_id = j.cache_artifact_id))
            ORDER BY j.updated_at, j.id
            LIMIT @limit
            """,
            new { orgId, threshold, limit });
        return rows.Select(r => (new OciScanOwner(r.OwnerKind, r.OwnerId), r.Repository, r.Digest)).ToList();
    }

    /// <summary>
    /// The oldest last OSV match among the images <paramref name="orgId"/> still holds, or null
    /// when it holds no scanned image.
    /// </summary>
    public async Task<string?> GetOldestMatchAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<string?>(
            """
            SELECT MIN(COALESCE(c.matched_at, c.scanned_at))
            FROM oci_scan_coverage c
            WHERE c.org_id = @orgId
              AND (
                  (c.owner_kind = 'package_version' AND EXISTS (
                      SELECT 1 FROM package_versions pv
                      JOIN packages p ON p.id = pv.package_id
                      WHERE pv.id = c.package_version_id AND p.org_id = @orgId))
                  OR
                  (c.owner_kind = 'cache_artifact' AND EXISTS (
                      SELECT 1 FROM tenant_artifact_access taa
                      WHERE taa.org_id = @orgId AND taa.cache_artifact_id = c.cache_artifact_id)))
            """,
            new { orgId });
    }

    /// <summary>The platforms of <paramref name="orgId"/>'s stored result for <paramref name="owner"/>, by platform.</summary>
    public async Task<IReadOnlyList<OciInventoryPlatform>> GetInventoryPlatformsAsync(
        string orgId, OciScanOwner owner, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<OciInventoryPlatform>(
            """
            SELECT id AS Id, platform AS Platform, extraction_version AS ExtractionVersion,
                   scanner_version AS ScannerVersion, content_gaps_json AS ContentGapsJson,
                   entrypoint_kind AS EntrypointKind, closure_bounded AS ClosureBounded
            FROM oci_scan_coverage
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            ORDER BY platform
            """,
            OwnerArgs(orgId, owner));
        return rows.AsList();
    }

    /// <summary>
    /// The components of <paramref name="orgId"/>'s stored result for <paramref name="owner"/>,
    /// ordered by platform as <see cref="GetInventoryPlatformsAsync"/> orders them, streamed from
    /// one unbuffered query outside any transaction and capped at <paramref name="max"/>. A
    /// re-extraction that replaces the rows meanwhile is caught when the result's coverage ids
    /// are checked, not here.
    /// </summary>
    public async IAsyncEnumerable<OciInventoryComponent> StreamInventoryComponentsAsync(
        string orgId, OciScanOwner owner, int max, [EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var args = new DynamicParameters(OwnerArgs(orgId, owner));
        args.Add("max", max);
        await foreach (var component in conn.QueryUnbufferedAsync<OciInventoryComponent>(
            """
            SELECT id AS Id, platform AS Platform, purl AS Purl, ecosystem AS Ecosystem, name AS Name,
                   version AS Version, source_name AS SourceName, source_version AS SourceVersion
            FROM oci_image_components
            WHERE org_id = @orgId AND owner_kind = @ownerKind
              AND (package_version_id = @packageVersionId OR cache_artifact_id = @cacheArtifactId)
            ORDER BY platform, id
            LIMIT @max
            """,
            args).WithCancellation(ct))
        {
            yield return component;
        }
    }

    private static object OwnerArgs(string orgId, OciScanOwner owner) => new
    {
        orgId,
        ownerKind = owner.Kind,
        packageVersionId = owner.PackageVersionId,
        cacheArtifactId = owner.CacheArtifactId,
    };

    // Setters rather than a positional record, for the same INTEGER width reason as JobRow.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed",
        Justification = "Dapper materializes these projection properties by reflection, converting each column to the "
                        + "property type (int against long across providers).")]
    private sealed class CandidateRow
    {
        public string OwnerKind { get; set; } = "";
        public string OwnerId { get; set; } = "";
        public string Repository { get; set; } = "";
        public string Digest { get; set; } = "";
        public string OldestMatch { get; set; } = "";
        public long LegacyRows { get; set; }
    }
}
