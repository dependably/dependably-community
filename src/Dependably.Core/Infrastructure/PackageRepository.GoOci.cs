using Dapper;

namespace Dependably.Infrastructure;

// Go module proxy and OCI-specific catalogue helpers (version listing, latest-version lookup,
// tag-by-digest projection, digest-claim release). Split out of PackageRepository.cs (partial
// class) to keep any single file under the 1000-line cap; see that file for CRUD, construction,
// and the shared _db/_downloadCountWriter/_time fields.
public sealed partial class PackageRepository
{
    // ── Go module proxy helpers ──────────────────────────────────────────────

    /// <summary>
    /// Returns a list of cached Go module versions for the given module path, ordered
    /// newest-first by creation time. Used by the <c>/@v/list</c> endpoint.
    /// </summary>
    public async Task<IReadOnlyList<string>> ListVersionsForGoModuleAsync(
        string orgId, string module, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var pvVersions = await conn.QueryAsync<string>(
            // plane-ok: PV-plane Go versions; global-plane proxy versions are merged via the sibling cache_artifact SELECT in this method.
            """
            SELECT pv.version
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'golang'
              AND p.purl_name = @module
            ORDER BY pv.created_at DESC
            """,
            new { orgId, module });

        // Also include versions from the global plane for proxy .zips cached after the P3b flip.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var globalVersions = await conn.QueryAsync<string>(
            """
            SELECT ca.version
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'golang'
              AND ca.name = @module
            ORDER BY ca.first_cached_at DESC
            """,
            new { orgId, module });

        var pvList = pvVersions.ToList();
        var globalList = globalVersions.ToList();
        if (globalList.Count == 0)
        {
            return pvList;
        }
        if (pvList.Count == 0)
        {
            return globalList;
        }

        // Union: local (package_versions) wins on collision; deduplicate.
        var pvSet = new HashSet<string>(pvList, StringComparer.OrdinalIgnoreCase);
        var merged = new List<string>(pvList);
        foreach (string v in globalList)
        {
            if (!pvSet.Contains(v))
            {
                merged.Add(v);
            }
        }
        return merged;
    }

    /// <summary>
    /// Returns the most-recently-created cached version for the given Go module, or null
    /// when nothing is cached. Used by the <c>/@latest</c> endpoint. Checks both the
    /// legacy <c>package_versions</c> path and the global plane (<c>cache_artifact</c>)
    /// for proxy .zips cached after the P3b flip; returns the newest across both planes.
    /// </summary>
    public async Task<PackageVersion?> GetLatestGoVersionAsync(
        string orgId, string module, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var pvLatest = await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            // plane-ok: PV-plane latest Go version; the global-plane latest is compared via the sibling cache_artifact SELECT in this method.
            """
            SELECT pv.id AS Id, pv.package_id AS PackageId,
                   pv.version AS Version, pv.purl AS Purl,
                   pv.blob_key AS BlobKey, pv.size_bytes AS SizeBytes,
                   pv.checksum_sha256 AS ChecksumSha256,
                   pv.created_at AS CreatedAt
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'golang'
              AND p.purl_name = @module
            ORDER BY pv.created_at DESC
            LIMIT 1
            """,
            new { orgId, module });

        // Also check global-plane proxy .zips for versions cached after the P3b flip.
        // xtenant: cache_artifact is global; org_id filter is on tenant_artifact_access.
        var caLatest = await conn.QuerySingleOrDefaultAsync<(string Version, string FirstCachedAt)>(
            """
            SELECT ca.version AS Version, ca.first_cached_at AS FirstCachedAt
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id AND taa.org_id = @orgId
            WHERE ca.ecosystem = 'golang'
              AND ca.name = @module
            ORDER BY ca.first_cached_at DESC
            LIMIT 1
            """,
            new { orgId, module });

        if (caLatest.Version is null)
        {
            return pvLatest;
        }

        if (pvLatest is null)
        {
            // Build a synthetic PackageVersion from the global-plane row so @latest can serve it.
            return new PackageVersion
            {
                Id = string.Empty,
                PackageId = string.Empty,
                Version = caLatest.Version,
                Purl = string.Empty,
                BlobKey = string.Empty,
                CreatedAt = DateTimeOffset.Parse(
                    caLatest.FirstCachedAt,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal),
            };
        }

        // Return whichever is more recent between the PV row and the global-plane row.
        var caTime = DateTimeOffset.Parse(
            caLatest.FirstCachedAt,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
        return caTime > pvLatest.CreatedAt
            ? new PackageVersion
            {
                Id = string.Empty,
                PackageId = string.Empty,
                Version = caLatest.Version,
                Purl = string.Empty,
                BlobKey = string.Empty,
                CreatedAt = caTime,
            }
            : pvLatest;
    }

    /// <summary>
    /// Gets or creates a <c>packages</c> row for the Go module, then inserts a
    /// <c>package_versions</c> row for the given version. Idempotent via ON CONFLICT DO NOTHING
    /// so concurrent first-fetches of the same version are safe.
    /// </summary>
    public async Task GetOrCreateGoVersionAsync(
        string orgId, string module, string version, string purl, string blobKey,
        string? userId, CancellationToken ct = default)
    {
        var pkg = await GetOrCreateAsync(
            orgId, "golang", module, module, isProxy: true, ct);

        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        string filename = DeriveFilename(blobKey);
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: INSERT pinned to package_id resolved by GetOrCreateAsync under the caller's org.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, first_fetch, origin, created_at)
            VALUES
                (@id, @packageId, @version, @purl, @blobKey, @filename, 0, 1, 'proxy', @now)
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                packageId = pkg.Id,
                version,
                purl,
                blobKey,
                filename,
                now,
            });
    }

    /// <summary>
    /// Returns all tags in <c>oci_tags</c> for the given org and repository, grouped by
    /// digest. Callers join the result against <c>package_versions.version</c> (which equals
    /// the digest for OCI) to surface tag names alongside each image version row.
    /// </summary>
    public async Task<ILookup<string, string>> GetOciTagsByDigestAsync(
        string orgId, string repository, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Digest, string Tag)>(
            // rawsql: ORDER BY tag is a whitelisted constant, not user input.
            """
            SELECT digest, tag FROM oci_tags
            WHERE org_id = @orgId AND repository = @repo
            ORDER BY tag
            """,
            new { orgId, repo = repository });
        return rows.ToLookup(r => r.Digest, r => r.Tag);
    }

    /// <summary>
    /// Releases this org's claim on an OCI digest within one repository: removes this org's
    /// <c>oci_tags</c> rows for <paramref name="repository"/>/<paramref name="digest"/>, then —
    /// only when no other claim on the digest survives anywhere in this org — removes this org's
    /// <c>oci_blobs</c> row too. Used by the management-API <c>DeleteVersion</c>, for both the
    /// hosted (found via <c>package_versions</c>) and proxy/cache-plane branches, so a deleted
    /// OCI version never leaves a dangling <c>oci_tags</c>/<c>oci_blobs</c> row behind, and never
    /// destroys a row another repository, this org's own hosted image, or another org still
    /// depends on.
    ///
    /// <c>oci_blobs</c>' primary key is <c>(digest, org_id)</c> — ONE row per digest per org,
    /// shared by every repository and by both write paths. A proxy pull and a hosted push each
    /// upsert the same row via <c>ON CONFLICT(digest, org_id)</c>, and NEITHER clause rewrites
    /// <c>origin</c> — it stays whichever wrote it first. So this org's row surviving with
    /// <c>origin='proxy'</c> does NOT mean no hosted claim exists: a pull-then-push round-trip
    /// (proxy-pull an image, retag, push it to a private repo) leaves <c>origin='proxy'</c>
    /// forever even though a hosted <c>package_versions</c> row now depends on the same digest.
    /// This is why the claim check below never inspects the row's own <c>origin</c> column — it
    /// looks at the actual surviving claims instead (a live <c>oci_tags</c> row under ANY
    /// repository in this org, or a <c>package_versions</c> row with <c>origin='uploaded'</c>
    /// whose version equals the digest, under ANY repository in this org).
    ///
    /// Callers MUST remove/finish whatever row triggered this call (the <c>package_versions</c>
    /// row itself, for a hosted delete) BEFORE calling this, so that row cannot count as its own
    /// surviving claim.
    ///
    /// Returns the content-addressed <c>blob_key</c> when this org's just-removed row was
    /// <c>origin='uploaded'</c> — a Registry-tier physical-delete candidate the caller hands to
    /// <see cref="Protocol.OciOrphanBlobDeleter.DeleteIfUnreferencedAsync"/>, which performs the
    /// locked cross-org refcount and removes the file only when this org held the last reference.
    /// Returns <see langword="null"/> when a claim survives, no <c>oci_blobs</c> row exists, or the
    /// row was a proxy-origin manifest — proxy-tier bytes live in the Cache tier and are reclaimed
    /// by cache GC, never deleted here. Routing physical deletion through the shared deleter (the
    /// same path the protocol-level digest delete and hosted-version delete take) keeps every OCI
    /// blob delete on one locked cross-org counting query. Layer/config blobs referenced by the
    /// manifest are never reclaimed here — layer refcounting is out of scope.
    /// </summary>
    public async Task<string?> ReleaseOciDigestClaimAsync(
        string orgId, string repository, string digest, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Tags are always safe to remove regardless of any other claim — org+repository+tag
        // scoped, no cross-tenant or cross-repository sharing.
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            "DELETE FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND digest = @digest",
            new { orgId, repo = repository, digest });

        // plane-ok: OCI claim-survival check, not a serve read — the proxy plane is covered by the
        // oci_tags EXISTS arm (a proxy pull casts an oci_tags row), the package_versions arm covers
        // hosted (uploaded) claims; together they are the two catalogues a digest can be claimed by.
        // xtenant: both EXISTS sub-selects are org_id-filtered — this org's surviving claims only.
        bool stillClaimed = await conn.ExecuteScalarAsync<bool>(
            """
            SELECT EXISTS(SELECT 1 FROM oci_tags WHERE org_id = @orgId AND digest = @digest)
                OR EXISTS(
                    SELECT 1 FROM package_versions pv
                    JOIN packages p ON p.id = pv.package_id
                    WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
                      AND pv.origin = 'uploaded' AND pv.version = @digest
                )
            """,
            new { orgId, digest });

        if (stillClaimed)
        {
            return null;
        }

        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (blobKey, origin) = await conn.QuerySingleOrDefaultAsync<(string? BlobKey, string? Origin)>(
            "SELECT blob_key AS BlobKey, origin AS Origin FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (blobKey is null)
        {
            return null;
        }

        // xtenant: (digest, org_id) PK.
        await conn.ExecuteAsync(
            "DELETE FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        // Only uploaded (Registry-tier) blobs are physical-delete candidates; a proxy-origin
        // manifest's Cache-tier bytes are left for the cache plane's own retention to reclaim.
        return origin == "uploaded" ? blobKey : null;
    }
}
