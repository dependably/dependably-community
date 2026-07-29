using Dapper;

namespace Dependably.Infrastructure;

// Version/package delete paths (rollback, proxy-version purge, empty-package GC) and version
// lifecycle state updates (manual block, yank, deprecation, upstream-latest tracking). Split out
// of PackageRepository.cs (partial class) to keep any single file under the 1000-line cap; see
// that file for CRUD, construction, and the shared _db/_downloadCountWriter/_time fields.
public sealed partial class PackageRepository
{
    /// <summary>
    /// Lookup a version by its primary key, scoped to <paramref name="orgId"/> via the parent
    /// package. version id is a Guid so collisions are not the concern — the org filter is the
    /// defence-in-depth tenancy invariant. Returns null when the id exists in a different org.
    /// </summary>
    public async Task<PackageVersion?> GetVersionByIdAsync(string orgId, string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            // plane-ok: point lookup by version PK, org-scoped via packages; the proxy plane is keyed by cache_artifact id elsewhere.
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.filename as Filename,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.updated_at as UpdatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.revoked_at as RevokedAt, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner,
                   pv.manifest_json as ManifestJson,
                   pv.versions_behind as VersionsBehind
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.id = @versionId AND p.org_id = @orgId
            """,
            new { orgId, versionId });
    }

    /// <summary>
    /// Deletes the <c>packages</c> row IFF no <c>package_versions</c> rows reference it AND no
    /// cache-plane version does either — this org's <c>tenant_artifact_access</c> joined to
    /// <c>cache_artifact</c> on <c>(ecosystem, purl_name)</c>. Without the cache-plane half, a
    /// proxy-only package (which never has <c>package_versions</c> rows) would GC its
    /// <c>packages</c> row on every single-version delete regardless of how many other
    /// cache-plane versions remain — silently re-creating the "0 versions" symptom this method
    /// exists to avoid, since the package would vanish from the Packages page even while other
    /// versions are still pullable. Both checks run in the same statement (NOT EXISTS,
    /// correlated on the row being deleted) so this stays atomic and race-safe against a
    /// concurrent publish or proxy first-fetch racing the last-version delete. Returns true when
    /// the parent row was removed.
    ///
    /// Claims live in a separate table FK'd to <c>orgs(id)</c>, not <c>packages(id)</c>,
    /// so a claim on the same name survives package GC by design — claims are about
    /// reserving a name, not anchoring storage.
    /// </summary>
    public async Task<bool> DeletePackageIfEmptyAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: DELETE keyed by packages.id (a Guid issued by GetOrCreate under an
        // org-scoped lookup); both NOT EXISTS sub-selects correlate back to that same row
        // (package_id = @id, or packages.org_id/ecosystem/purl_name of the row being deleted) —
        // never a cross-tenant scan.
        int affected = await conn.ExecuteAsync(
            """
            DELETE FROM packages
            WHERE id = @id
              AND NOT EXISTS (SELECT 1 FROM package_versions WHERE package_id = @id)
              AND NOT EXISTS (
                  SELECT 1 FROM tenant_artifact_access taa
                  JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                  WHERE taa.org_id = packages.org_id
                    AND ca.ecosystem = packages.ecosystem
                    AND ca.name = packages.purl_name
              )
            """,
            new { id = packageId });
        return affected > 0;
    }

    /// <summary>
    /// Deletes a version ROW and nothing else — the publish rollback path only.
    /// <see cref="DeleteVersionAsync"/> also recomputes the parent package's <c>is_proxy</c>
    /// flag, which a rolled-back publish has no business touching: its row never became part of
    /// the package's visible version set. The tenant's storage bytes need no adjustment on either
    /// path — they are derived from the surviving rows, so deleting the row IS the release.
    /// </summary>
    public async Task DeleteVersionRowForPublishRollbackAsync(string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK (globally unique surrogate); the caller created this
        // row moments ago in the same publish.
        await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = versionId });
    }

    /// <summary>
    /// Deletes a <c>package_versions</c> row and recomputes <c>packages.is_proxy</c> so it is
    /// <c>true</c> exactly when no <c>origin='uploaded'</c> versions remain for the parent
    /// package. The tenant's storage usage needs no decrement: it is derived live from
    /// <c>org_storage_bytes</c>, so the deleted row's bytes leave the sum with the row.
    ///
    /// Deleting an <c>origin='uploaded'</c> version also records a
    /// <c>package_version_tombstone</c> row in the same transaction, so the coordinate survives
    /// the deletion of both the version row and (when it was the last version) its parent
    /// <c>packages</c> row. The publish dedup gate reads that tombstone to refuse a republish of
    /// the coordinate under a blocking version-overwrite policy. Proxy-origin rows are cache
    /// entries, not publishes, and are never tombstoned.
    /// </summary>
    public async Task DeleteVersionAsync(string versionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Resolve the parent package before the delete so is_proxy can be recomputed after the
        // row is gone, and the coordinate so the tombstone can be recorded from it. Version rows
        // are immutable once created, so a read that predates the transaction below by a few
        // statements is still valid input. Reading outside the transaction also lets two
        // concurrent deletes' reads genuinely overlap instead of serializing on each other's
        // transaction the way two open write transactions would.
        // xtenant: keyed by version PK (pv.id), a globally unique surrogate; caller already
        // verified org ownership before invoking this method. The joined packages row supplies
        // the org the tombstone is written under.
        var coordinate = await conn.QuerySingleOrDefaultAsync<DeletedVersionCoordinate>(
            // plane-ok: point lookup by version PK on the hosted-version delete path; proxy deletes go through the cache plane.
            """
            SELECT pv.package_id AS PackageId, p.org_id AS OrgId, p.ecosystem AS Ecosystem,
                   p.purl_name AS PurlName, pv.version AS Version,
                   pv.checksum_sha256 AS ContentHash, pv.origin AS Origin
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.id = @id
            """,
            new { id = versionId });
        string? packageId = coordinate?.PackageId;

        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            // Two concurrent deletes of the same version can both resolve packageId above before
            // either DELETE lands. Gating the recompute on this connection's own DELETE affecting
            // a row (rather than on the earlier SELECT) keeps the pair in one transaction, so a
            // crash between them cannot leave is_proxy describing a version set that no longer
            // exists.
            // xtenant: keyed by version PK (id), a globally unique surrogate the caller already
            // resolved through an org-scoped lookup before invoking this method.
            int affected = await conn.ExecuteAsync(
                "DELETE FROM package_versions WHERE id = @id", new { id = versionId }, dbTx);

            if (affected == 1 && packageId is not null)
            {
                // xtenant: keyed by packages.id (the package PK resolved above from an
                // org-scoped version PK); the NOT EXISTS sub-select stays bound to that same id.
                await conn.ExecuteAsync(
                    """
                    UPDATE packages
                    SET is_proxy = NOT EXISTS (
                        SELECT 1 FROM package_versions
                        WHERE package_id = @pkgId AND origin = 'uploaded'
                    )
                    WHERE id = @pkgId
                    """,
                    new { pkgId = packageId }, dbTx);
            }

            // Tombstone the coordinate only when this delete actually removed a hosted version.
            // The DELETE's own affected count (not the pre-transaction read) is the gate, so two
            // concurrent deletes of the same row record exactly one tombstone, and a delete that
            // lost the race records none.
            if (affected == 1 && coordinate is { Origin: "uploaded" })
            {
                await VersionTombstoneRepository.RecordAsync(
                    conn, dbTx, coordinate.OrgId, coordinate.Ecosystem, coordinate.PurlName,
                    coordinate.Version, coordinate.ContentHash,
                    _time.GetUtcNow().ToUtcIso());
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    /// <summary>
    /// Deletes every <c>origin = 'proxy'</c> version row for (org, ecosystem, purl_name)
    /// and returns the blob keys that were just dereferenced. Caller is expected to delete the
    /// blobs after this completes — doing it here would couple the repo to <c>IBlobStore</c> and
    /// leave the path harder to test. Imported / private artefacts are never touched.
    /// </summary>
    public async Task<IReadOnlyList<string>> DeleteProxyVersionsForNameAsync(
        string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: PV-plane legacy proxy purge; the cache plane is evicted by the sibling CacheArtifactRepository.EvictTenantProxyVersionsForNameAsync in ClaimsController.PurgeProxyArtefactsAsync.
        var blobKeys = (await conn.QueryAsync<string>("""
            SELECT pv.blob_key
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = @ecosystem
              AND p.purl_name = @purlName
              AND pv.origin = 'proxy'
            """, new { orgId, ecosystem, purlName })).ToList();

        if (blobKeys.Count > 0)
        {
            await conn.ExecuteAsync("""
                DELETE FROM package_versions
                WHERE id IN (
                    SELECT pv.id
                    FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.org_id = @orgId
                      AND p.ecosystem = @ecosystem
                      AND p.purl_name = @purlName
                      AND pv.origin = 'proxy'
                )
                """, new { orgId, ecosystem, purlName });
        }
        return blobKeys;
    }

    /// <summary>
    /// Streams every blob key any metadata row references, instance-wide — the union of all
    /// four tables that can hold one. Backs the orphan-blob reconciler: the caller materializes
    /// this as a set, walks the registry tier, and deletes every blob NOT in it. A key missing
    /// from this union is a blob that gets deleted, so completeness here is a data-integrity
    /// requirement, not an optimisation.
    /// <list type="bullet">
    ///   <item><c>package_versions.blob_key</c> — the primary artefact of a version.</item>
    ///   <item><c>package_version_files.blob_key</c> — the per-file rows of a multi-file PyPI
    ///     release (sdist + wheels). Only the first file published lands its key on the
    ///     <c>package_versions</c> row; every sibling file exists here alone.</item>
    ///   <item><c>maven_version_files.blob_key</c> — the per-file rows of a Maven version (JAR +
    ///     POM + sources + javadoc + classifiers). The <c>package_versions</c> row is shared
    ///     across all files of the version and carries only the first-published file's key.</item>
    ///   <item><c>nuget_symbol_index.snupkg_blob_key</c> — the stored <c>.snupkg</c> holding an
    ///     indexed Portable PDB.</item>
    /// </list>
    /// <c>oci_blobs</c> and <c>cache_artifact</c> are deliberately absent: their keys carry the
    /// <c>oci/</c> and <c>proxy/</c> prefixes, outside the <c>hosted/</c> prefix the reconciler
    /// walks. Proxy-origin rows within the tables above (a proxy-cached version's <c>proxy/</c>
    /// key, a cache-artifact-owned Maven file row) stream back too; they match no <c>hosted/</c>
    /// blob and are inert in the set.
    /// <para>
    /// UNION ALL, not UNION: cross-arm duplicates (a <c>.snupkg</c> key is in both
    /// <c>package_versions</c> and <c>nuget_symbol_index</c>) are collapsed by the caller's
    /// hash set, whereas UNION would make the database sort and materialize the whole result,
    /// defeating the unbuffered read that keeps memory bounded on large stores.
    /// </para>
    /// </summary>
    public async IAsyncEnumerable<string> StreamAllBlobKeysAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: instance-wide by design. The registry blob tier is shared across every tenant,
        // so the reconciler's referenced set has to span every tenant — an org-filtered set would
        // classify every OTHER tenant's artefacts as orphans and delete them.
        await foreach (string key in conn.QueryUnbufferedAsync<string>(
            // plane-ok: orphan reconciler walks only the hosted/ blob prefix; cache_artifact/oci_blobs keys carry proxy//oci/ prefixes and are deliberately out of scope.
            """
            SELECT blob_key FROM package_versions
            UNION ALL
            SELECT blob_key FROM package_version_files
            UNION ALL
            SELECT blob_key FROM maven_version_files
            UNION ALL
            SELECT snupkg_blob_key FROM nuget_symbol_index
            """,
            commandTimeout: 0))
        {
            if (ct.IsCancellationRequested)
            {
                yield break;
            }

            yield return key;
        }
    }

    public async Task SetManualBlockStateAsync(string versionId, string? state, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK. VulnerabilityController resolves it via
        // ResolveTenantPackageVersionAsync (org-scoped); QuarantineController takes it off a
        // quarantine row fetched with GetByIdAsync(orgId, id), which 404s a cross-tenant id.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = @state WHERE id = @id",
            new { id = versionId, state });
    }

    /// <summary>
    /// Sets or clears the per-package same-version-push override for an org-scoped package row.
    /// <paramref name="overrideValue"/> is one of <c>'allow'</c>, <c>'block'</c>, or <c>null</c>
    /// (null clears the override, restoring inheritance from the org policy).
    /// </summary>
    public async Task SetSameVersionPushOverrideAsync(
        string packageId, string orgId, string? overrideValue, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "UPDATE packages SET same_version_push_override = @override WHERE id = @id AND org_id = @orgId",
            new { id = packageId, orgId, @override = overrideValue });
    }

    /// <summary>
    /// Flips the <c>yanked</c> flag on a version, clearing <c>yank_reason</c> when unyanking.
    /// Yank hides a version from dependency resolution (Cargo, npm) without deleting the
    /// artefact — a yanked crate is still downloadable by exact coordinate. The caller resolves
    /// the version id from an already org-scoped lookup, so no org filter is needed here.
    /// </summary>
    public async Task SetYankedAsync(string versionId, bool yanked, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Stamp yanked_at on yank, clear it on un-yank, so the unlist-age retention gate
        // measures time since the most recent unlist rather than since publish.
        string? yankedAt = yanked ? _time.GetUtcNow().ToUtcIso() : null;
        // xtenant: keyed by version PK; CargoController resolves it via
        // GetByPurlNameAsync(orgId, …) → GetVersionAsync(pkg.Id, …) and 404s an unknown name.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET yanked = @yanked, yank_reason = NULL, yanked_at = @yankedAt WHERE id = @id",
            new { id = versionId, yanked = yanked ? 1 : 0, yankedAt });
    }

    /// <summary>
    /// Stamps <c>deprecation_checked_at</c> to now without changing the <c>deprecated</c> value.
    /// Called when an upstream metadata fetch confirms the deprecation status is unchanged.
    /// </summary>
    public async Task UpdateDeprecationCheckedAtAsync(string versionId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK, supplied by the deprecation refresh pass that enumerated
        // the version from an org-scoped query.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecation_checked_at = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Updates both <c>deprecated</c> and <c>deprecation_checked_at</c> in a single UPDATE.
    /// Called when upstream metadata shows a changed deprecation state.
    /// </summary>
    public async Task UpdateDeprecatedAndCheckedAsync(string versionId, string? deprecated, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK, supplied by the deprecation refresh pass that enumerated
        // the version from an org-scoped query.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @deprecated, deprecation_checked_at = @now WHERE id = @id",
            new { id = versionId, deprecated, now });
    }

    /// <summary>
    /// Writes the operational-risk versions-behind count on a hosted (<c>origin='uploaded'</c>)
    /// <c>package_versions</c> row. Mirrors <see
    /// cref="CacheArtifactRepository.UpdateVersionsBehindAsync"/> for the proxy plane.
    /// <paramref name="versionsBehind"/> is null when the count is unknown — never coerced to 0.
    /// </summary>
    public async Task UpdateVersionsBehindAsync(string versionId, int? versionsBehind, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET versions_behind = @versionsBehind WHERE id = @id",
            new { id = versionId, versionsBehind });
    }

    /// <summary>
    /// Records upstream's declared latest version (and, when known, its publish timestamp) for a
    /// package and stamps the refresh time. Called by DeprecationRefreshService on each
    /// upstream-metadata pass and by the first-fetch seed. A null <paramref name="latestVersion"/>
    /// clears the baseline (upstream had no latest claim); <paramref name="publishedAt"/> is
    /// independently nullable — a resolved version with an unknown publish time (the ecosystem's
    /// metadata doesn't carry one, or the timestamp fetch failed) still clears/sets it to null
    /// rather than leaving a stale value from a previous latest version.
    /// </summary>
    public async Task UpdateUpstreamLatestAsync(
        string packageId, string? latestVersion, DateTimeOffset? publishedAt = null, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        // Microsecond precision, matching CacheArtifactRepository.UpdateGlobalFactsAsync's writer
        // of the same logical published_at/upstream_latest_published_at column (see
        // artifact_inventory / QuarantineRepository's cross-plane MAX() aggregation) — this
        // instant is upstream-declared, not derived from our own clock, so seconds would drop
        // information the registry reports.
        string? publishedAtIso = publishedAt.ToUtcIsoPreciseOrNull();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE keyed by the package id (already org-scoped via FK); caller resolves
        // the package within a single org's refresh pass.
        await conn.ExecuteAsync(
            """
            UPDATE packages
            SET upstream_latest_version = @latestVersion,
                upstream_latest_checked_at = @now,
                upstream_latest_published_at = @publishedAtIso
            WHERE id = @id
            """,
            new { id = packageId, latestVersion, now, publishedAtIso });
    }

    /// <summary>
    /// Returns (ecosystem, purl_name, org_id) groups for HOSTED packages whose upstream-latest
    /// tracking has gone stale but that no current <c>cache_artifact</c> group covers. The
    /// deprecation-refresh pass otherwise enumerates only <c>cache_artifact</c> groups, so a
    /// package that was once proxied — hence carries a seeded <c>upstream_latest_checked_at</c> —
    /// and then had its proxy rows evicted, keeping only <c>origin='uploaded'</c> versions, would
    /// never be revisited and its <c>upstream_latest_version</c> / hosted <c>versions_behind</c>
    /// would freeze at eviction time.
    ///
    /// Restricted to the upstream-latest-supported ecosystems and to packages already proven to
    /// track an upstream (<c>upstream_latest_checked_at IS NOT NULL</c>), so a purely-internal name
    /// that was never proxied is never fetched. Excludes soft-deleted / air-gapped tenants and
    /// packages carrying no hosted version. Ordered oldest-checked first so a partial run makes
    /// progress on the most stale packages.
    /// </summary>
    // xtenant: cross-tenant enumeration for the deprecation-refresh background pass; the caller
    // processes each (ecosystem, name, orgId) group independently. The NOT EXISTS subquery scopes
    // the cache plane by the same packages.org_id.
    public async Task<IReadOnlyList<(string Ecosystem, string Name, string OrgId)>>
        ListHostedGroupsNeedingUpstreamRefreshAsync(int ageHours, int limit, TimeProvider time, CancellationToken ct = default)
    {
        string threshold = time.GetUtcNow().AddHours(-ageHours).ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Ecosystem, string Name, string OrgId)>(
            """
            SELECT p.ecosystem AS Ecosystem, p.purl_name AS Name, p.org_id AS OrgId
            FROM packages p
            JOIN orgs o ON o.id = p.org_id
            LEFT JOIN org_settings os ON os.org_id = p.org_id
            WHERE p.ecosystem IN ('npm', 'pypi', 'nuget', 'maven')
              AND p.upstream_latest_checked_at IS NOT NULL
              AND p.upstream_latest_checked_at < @threshold
              AND o.deleted_at IS NULL
              AND COALESCE(os.air_gapped, 0) = 0
              AND EXISTS (SELECT 1 FROM package_versions pv
                          WHERE pv.package_id = p.id AND pv.origin = 'uploaded')
              AND NOT EXISTS (SELECT 1 FROM cache_artifact ca
                              JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                              WHERE taa.org_id = p.org_id AND ca.ecosystem = p.ecosystem AND ca.name = p.purl_name)
            ORDER BY p.upstream_latest_checked_at ASC
            LIMIT @limit
            """,
            new { threshold, limit });
        return rows.ToList();
    }

    /// <summary>
    /// Deletes the OCI manifest shadow rows for a version being removed through the management delete
    /// path — this org's <c>oci_tags</c> for the digest and its <c>oci_blobs</c> row — and returns the
    /// manifest blob key when it is an uploaded (Registry-tier) blob, i.e. a candidate for physical
    /// deletion. Returns null for a proxy-tier blob, which is never physically deleted here; the cache
    /// plane GCs it.
    ///
    /// Resolving a candidate is NOT a decision to delete it. OCI blob keys are content-addressed with
    /// no org segment, so two orgs pushing the same digest share one physical blob: the returned key
    /// goes to <c>OciOrphanBlobDeleter</c>, which counts the remaining cross-org references and
    /// removes the file only under the per-key lock. Counting here and deleting in the caller would
    /// leave that gap unserialised against a concurrent push.
    ///
    /// The generic version-delete path (which deletes <c>package_versions.blob_key</c> directly) would
    /// destroy the shared blob and 404 every other org's image, and would never clean the
    /// <c>oci_blobs</c>/<c>oci_tags</c> sidecars — hence this OCI-specific arm.
    /// </summary>
    public async Task<string?> DeleteOciManifestShadowAndResolveUploadedBlobAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: (digest, org_id) PK scopes this to the caller's org.
        var (blobKey, origin) = await conn.QuerySingleOrDefaultAsync<(string? BlobKey, string? Origin)>(
            "SELECT blob_key AS BlobKey, origin AS Origin FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        // xtenant: org_id filter isolates the caller's tag/blob rows.
        await conn.ExecuteAsync(
            "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repository AND digest = @digest",
            new { orgId, repository, digest });
        await conn.ExecuteAsync(
            "DELETE FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        // Proxy-tier manifests live in the cache tier and are reclaimed by cache GC, never deleted
        // here; only an uploaded blob is a candidate for physical registry-tier deletion.
        return blobKey is null || origin != "uploaded" ? null : blobKey;
    }

    // The identity of a version resolved just before its row is deleted: the parent package id
    // for the is_proxy recompute, plus the (org, ecosystem, purl_name, version) coordinate and
    // digest the tombstone is written from. Origin discriminates a hosted publish from a
    // cache-plane row, which is never tombstoned.
    private sealed class DeletedVersionCoordinate
    {
        public string? PackageId { get; init; }
        public string OrgId { get; init; } = "";
        public string Ecosystem { get; init; } = "";
        public string PurlName { get; init; } = "";
        public string Version { get; init; } = "";
        public string? ContentHash { get; init; }
        public string? Origin { get; init; }
    }
}
