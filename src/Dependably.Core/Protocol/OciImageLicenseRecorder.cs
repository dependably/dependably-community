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

    public OciImageLicenseRecorder(
        IMetadataStore db,
        TieredBlobStorage blobs,
        TimeProvider time,
        ILogger<OciImageLicenseRecorder> logger)
    {
        _db = db;
        _blobs = blobs;
        _time = time;
        _logger = logger;
    }

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

            int awaiting = await conn.ExecuteScalarAsync<int>(
                """
                SELECT COUNT(*) FROM oci_blobs
                WHERE org_id = @orgId AND config_digest = @configDigest AND license_checked_at IS NULL
                """,
                new { orgId, configDigest });
            if (awaiting == 0)
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
