using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;

namespace Dependably.Protocol;

/// <summary>
/// Captures the SPDX license expression an OCI image declares in its config blob
/// (<c>config.Labels["org.opencontainers.image.licenses"]</c>) onto the manifest's
/// <c>oci_blobs</c> row. License facts live as additive columns on that row
/// (<c>config_digest</c> / <c>license_spdx</c> / <c>license_checked_at</c>) rather than on the
/// package_versions / cache_artifact planes, because an OCI image's identity is its manifest.
///
/// There are two capture points, both routed here so the stamping SQL lives in one place:
///   • <see cref="RecordManifestAsync"/> runs whenever a manifest row is written (proxy cache and
///     hosted push). It parses the config digest out of the manifest, stamps it onto the manifest
///     row, and — when the config bytes are already present locally — reads the label and stamps
///     the license.
///   • <see cref="RecordConfigBlobArrivalAsync"/> runs when a config blob first lands in the proxy
///     cache. It reverse-looks-up the manifest rows awaiting a stamp (by <c>config_digest</c>) and
///     stamps them from the just-arrived bytes.
///
/// Both methods are best-effort: the whole body is wrapped so a failure never faults the pull or
/// push that triggered it. Every statement is parameterized and filters <c>org_id</c>.
///
/// Self-healing race: a manifest insert and a concurrent config fetch can interleave such that
/// neither capture point observes both facts (the manifest row exists but its config was not yet
/// stored when <see cref="RecordManifestAsync"/> ran, and <see cref="RecordConfigBlobArrivalAsync"/>
/// saw no manifest row yet). The manifest row is then left with <c>license_checked_at IS NULL</c>;
/// the next manifest re-fetch (tag-TTL revalidation) re-runs <see cref="RecordManifestAsync"/> and
/// completes the capture. Every stamp is guarded by <c>license_checked_at IS NULL</c> so a
/// completed stamp (including a label-less <c>NULL</c> license) is never overwritten or reparsed.
/// </summary>
public sealed class OciImageLicenseRecorder
{
    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly TimeProvider _time;
    private readonly ILogger<OciImageLicenseRecorder> _logger;
    private readonly LicenseRepository _licenses;

    public OciImageLicenseRecorder(
        IMetadataStore db,
        TieredBlobStorage blobs,
        TimeProvider time,
        ILogger<OciImageLicenseRecorder> logger,
        LicenseRepository licenses)
    {
        _db = db;
        _blobs = blobs;
        _time = time;
        _logger = logger;
        _licenses = licenses;
    }

    /// <summary>
    /// Projects the SPDX expression captured on the manifest's <c>oci_blobs</c> row onto whichever
    /// catalogue row the image cast, as an ordinary <c>package_version_licenses</c> fact.
    ///
    /// An image reaches the catalogue through either plane — a tag push writes a
    /// <c>package_versions</c> row, a proxy pull writes a <c>cache_artifact</c> row — and in both
    /// cases the row's version column holds the manifest digest. Writing the license to the shared
    /// table means every license reader (the package-detail page, the license-risk tile and its
    /// drill-down, the review queue) sees an image's license through the same query it already uses
    /// for every other ecosystem, instead of each one having to know that OCI keeps its license
    /// somewhere else.
    ///
    /// Runs after cataloguing: the capture points above stamp <c>oci_blobs</c> before the catalogue
    /// row exists, so there is nothing to attach the fact to at that moment. Idempotent — both
    /// writes are ON CONFLICT DO NOTHING. Best-effort, like the capture itself: a failure here never
    /// faults the push or pull that triggered it.
    /// </summary>
    public async Task ProjectLicenseToCatalogAsync(
        string orgId, string manifestDigest, CancellationToken ct)
    {
        try
        {
            await using var conn = await _db.OpenAsync(ct);

            // xtenant: (digest, org_id) is the oci_blobs PK — each org holds its own manifest row.
            string? spdx = await conn.ExecuteScalarAsync<string?>(
                "SELECT license_spdx FROM oci_blobs WHERE digest = @manifestDigest AND org_id = @orgId",
                new { manifestDigest, orgId });

            if (string.IsNullOrWhiteSpace(spdx))
            {
                return;
            }

            string? versionId = await conn.ExecuteScalarAsync<string?>(
                // plane-ok: projects the licence onto the PV-plane row; the proxy-plane cache_artifact row is handled by the sibling SELECT in this method.
                """
                SELECT pv.id
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND p.ecosystem = 'oci'
                  AND pv.version = @manifestDigest AND pv.origin = 'uploaded'
                """,
                new { orgId, manifestDigest });

            if (versionId is not null)
            {
                await _licenses.SetLicensesAsync(versionId, [spdx], OciLabelSource, ct);
            }

            string? cacheArtifactId = await conn.ExecuteScalarAsync<string?>(
                """
                SELECT ca.id
                FROM cache_artifact ca
                JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.version = @manifestDigest
                """,
                new { orgId, manifestDigest });

            if (cacheArtifactId is not null)
            {
                await _licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, [spdx], OciLabelSource, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} projecting the OCI image license onto the catalogue for {Digest}; the pull or push is unaffected. TraceId={TraceId}",
                ex.GetType().Name, manifestDigest,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
        }
    }

    /// <summary>Provenance recorded on a license row derived from an image's config label.</summary>
    internal const string OciLabelSource = "oci-label";

    /// <summary>
    /// Records the config digest from a freshly written image manifest and, when the config blob
    /// is already stored locally, stamps the license read from its
    /// <c>org.opencontainers.image.licenses</c> label. Index manifests (no config blob) and
    /// non-parseable bodies leave all three columns NULL — a multi-arch index's children stamp
    /// individually when each is pulled by digest.
    /// </summary>
    public async Task RecordManifestAsync(
        string orgId, string manifestDigest, byte[] manifestBytes, CancellationToken ct)
    {
        try
        {
            var refs = OciManifestParser.ParseReferences(manifestBytes);
            if (refs is null || refs.IsIndex || refs.ConfigDigest is null)
            {
                return;
            }

            string configDigest = refs.ConfigDigest;
            await using var conn = await _db.OpenAsync(ct);

            await conn.ExecuteAsync(
                """
                UPDATE oci_blobs SET config_digest = @configDigest
                WHERE digest = @manifestDigest AND org_id = @orgId AND config_digest IS NULL
                """,
                new { configDigest, manifestDigest, orgId });

            var config = await conn.QuerySingleOrDefaultAsync<ConfigBlobRow>(
                """
                SELECT blob_key AS BlobKey, origin AS Origin
                FROM oci_blobs WHERE digest = @configDigest AND org_id = @orgId
                """,
                new { configDigest, orgId });
            if (config is null)
            {
                return;
            }

            byte[]? configBytes = await ReadConfigBytesAsync(TierFor(config.Origin), config.BlobKey, ct);
            if (configBytes is null)
            {
                return;
            }

            string? spdx = OciImageConfigParser.ParseLicensesLabel(configBytes);
            string checkedAt = NowIso();
            await conn.ExecuteAsync(
                """
                UPDATE oci_blobs SET license_spdx = @spdx, license_checked_at = @checkedAt
                WHERE digest = @manifestDigest AND org_id = @orgId AND license_checked_at IS NULL
                """,
                new { spdx, checkedAt, manifestDigest, orgId });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} recording OCI image license for manifest {Digest} (org {OrgId}); pull/push unaffected.",
                ex.GetType().Name, manifestDigest, orgId);
        }
    }

    /// <summary>
    /// Stamps every manifest row in <paramref name="orgId"/> that is awaiting a license stamp and
    /// references the just-arrived config blob (<paramref name="configDigest"/>). Called only from
    /// the proxy blob-insert path, so the bytes are read from the cache tier. The indexed
    /// <c>(org_id, config_digest)</c> probe short-circuits when no manifest awaits this config —
    /// the only cost a non-config blob's first insert pays.
    /// </summary>
    public async Task RecordConfigBlobArrivalAsync(
        string orgId, string configDigest, string blobKey, CancellationToken ct)
    {
        try
        {
            await using var conn = await _db.OpenAsync(ct);

            // The digests this config is about to stamp. Read before the UPDATE, because the
            // license_checked_at IS NULL predicate that selects them is what the UPDATE clears —
            // and each one's catalogue row needs the license projected onto it afterwards.
            var awaiting = (await conn.QueryAsync<string>(
                """
                SELECT digest FROM oci_blobs
                WHERE org_id = @orgId AND config_digest = @configDigest AND license_checked_at IS NULL
                """,
                new { orgId, configDigest })).ToList();
            if (awaiting.Count == 0)
            {
                return;
            }

            byte[]? configBytes = await ReadConfigBytesAsync(_blobs.Cache, blobKey, ct);
            if (configBytes is null)
            {
                return;
            }

            string? spdx = OciImageConfigParser.ParseLicensesLabel(configBytes);
            string checkedAt = NowIso();
            await conn.ExecuteAsync(
                """
                UPDATE oci_blobs SET license_spdx = @spdx, license_checked_at = @checkedAt
                WHERE org_id = @orgId AND config_digest = @configDigest AND license_checked_at IS NULL
                """,
                new { spdx, checkedAt, orgId, configDigest });

            if (spdx is null)
            {
                return;
            }

            // This is the path that closes the self-healing race: the manifest was catalogued before
            // its config arrived, so the license is only knowable now.
            foreach (string manifestDigest in awaiting)
            {
                await ProjectLicenseToCatalogAsync(orgId, manifestDigest, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} stamping OCI image license from arriving config {Digest} (org {OrgId}); pull unaffected.",
                ex.GetType().Name, configDigest, orgId);
        }
    }

    // Origin drives the tier the same way OciController.BlobTierFor does: 'proxy' rows live in the
    // eviction-friendly cache tier, everything else (locally pushed) in the durable registry tier.
    private IBlobStore TierFor(string origin) =>
        origin == "proxy" ? _blobs.Cache : _blobs.Registry;

    // Reads the config blob bytes, capped by LimitedReadStream — the stored size_bytes on a proxy
    // config row can be 0 and cannot be trusted, so the read cap comes from the metadata limit.
    private static async Task<byte[]?> ReadConfigBytesAsync(IBlobStore tier, string blobKey, CancellationToken ct)
    {
        var stream = await tier.GetAsync(blobKey, ct);
        if (stream is null)
        {
            return null;
        }

        await using (stream)
        await using (var limited = new LimitedReadStream(stream, ZipEntryLimits.MaxMetadataEntryBytes, "oci image config"))
        {
            using var buffer = new MemoryStream();
            await limited.CopyToAsync(buffer, ct);
            return buffer.ToArray();
        }
    }

    private string NowIso() => _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");

    private sealed record ConfigBlobRow(string BlobKey, string Origin);
}
