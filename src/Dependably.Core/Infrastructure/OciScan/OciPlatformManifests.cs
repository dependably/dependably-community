using System.Text.Json;
using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Which manifest digest each scanned platform of an image is: the image's own digest for a
/// single-platform manifest, or the child manifest the image index lists for that platform.
/// <see cref="ManifestDigestFor"/> is null for a platform the index does not list.
/// </summary>
public sealed record OciPlatformMap(string OwnerDigest, IReadOnlyDictionary<string, string>? IndexChildren)
{
    public string? ManifestDigestFor(string platform) =>
        IndexChildren is null ? OwnerDigest : IndexChildren.GetValueOrDefault(platform);

    /// <summary>
    /// Parses an image's stored manifest bytes. An index maps each listed platform, spelled as the
    /// scanner reports it (<c>os/architecture</c>, and <c>os/architecture/variant</c> when the
    /// index carries a variant), to its child digest; anything else maps every platform to the
    /// image itself. Null when the bytes are not a manifest at all.
    /// </summary>
    public static OciPlatformMap? Parse(string ownerDigest, byte[] bytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!doc.RootElement.TryGetProperty("manifests", out var manifests) || manifests.ValueKind != JsonValueKind.Array)
            {
                return new OciPlatformMap(ownerDigest, null);
            }

            var children = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var m in manifests.EnumerateArray())
            {
                if (m.ValueKind != JsonValueKind.Object
                    || !m.TryGetProperty("digest", out var digest) || digest.ValueKind != JsonValueKind.String
                    || !m.TryGetProperty("platform", out var platform) || platform.ValueKind != JsonValueKind.Object
                    || Text(platform, "os") is not { } os || Text(platform, "architecture") is not { } arch)
                {
                    continue;
                }

                string child = digest.GetString()!;
                children.TryAdd($"{os}/{arch}", child);
                if (Text(platform, "variant") is { } variant)
                {
                    children.TryAdd($"{os}/{arch}/{variant}", child);
                }
            }

            return new OciPlatformMap(ownerDigest, children);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>
/// Reads an image's stored manifest to map its scanned platforms to manifest digests, so the
/// result writer can record on each coverage row which manifest that platform is, and the
/// coverage backfill can fill rows written before the column existed. The scanner contract does
/// not change: the mapping is derived server-side from the stored index.
/// </summary>
public sealed class OciPlatformManifestReader
{
    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _blobs;
    private readonly ILogger<OciPlatformManifestReader> _logger;

    public OciPlatformManifestReader(IMetadataStore db, TieredBlobStorage blobs, ILogger<OciPlatformManifestReader> logger)
    {
        _db = db;
        _blobs = blobs;
        _logger = logger;
    }

    /// <summary>
    /// The platform map of <paramref name="digest"/> as <paramref name="orgId"/> stores it, or
    /// null when the org holds no readable manifest bytes for it.
    /// </summary>
    public async Task<OciPlatformMap?> ReadAsync(string orgId, string digest, CancellationToken ct = default)
    {
        (string? BlobKey, string? Origin) row;
        await using (var conn = await _db.OpenAsync(ct))
        {
            // xtenant: (digest, org_id) PK is tenant-scoped.
            row = await conn.QuerySingleOrDefaultAsync<(string? BlobKey, string? Origin)>(
                "SELECT blob_key AS BlobKey, origin AS Origin FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
                new { digest, orgId });
        }

        if (row.BlobKey is null)
        {
            return null;
        }

        try
        {
            await using var stream = await (row.Origin == "proxy" ? _blobs.Cache : _blobs.Registry).GetAsync(row.BlobKey, ct)
                ?? await (row.Origin == "proxy" ? _blobs.Registry : _blobs.Cache).GetAsync(row.BlobKey, ct);
            if (stream is null)
            {
                return null;
            }

            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, ct);
            return OciPlatformMap.Parse(digest, buffer.ToArray());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException)
        {
            _logger.LogWarning(
                "Could not read manifest {Digest} for org {OrgId} to map its scanned platforms: {ExceptionType}",
                digest, orgId, ex.GetType().Name);
            return null;
        }
    }
}
