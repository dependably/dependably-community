using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Infrastructure.Seeding;

/// <summary>
/// Inserts a package row referencing an existing org. Caller must have already inserted
/// the org. Use <see cref="InsertVersionAsync"/> to attach a version.
/// </summary>
public static class PackageSeeder
{
    public static async Task<string> InsertAsync(
        IMetadataStore db,
        string orgId,
        string ecosystem,
        string name,
        bool isProxy = false,
        string? purlName = null,
        CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @orgId, @ecosystem, @name, @purlName, @isProxy)
            """,
            new { id, orgId, ecosystem, name, purlName = purlName ?? name, isProxy = isProxy ? 1 : 0 });
        return id;
    }

    public static async Task<string> InsertVersionAsync(
        IMetadataStore db,
        string packageId,
        string version,
        string purl,
        string origin = "uploaded",
        string blobKey = "blob/key",
        long sizeBytes = 100,
        string? checksumSha256 = null,
        CancellationToken ct = default)
    {
        var id = Guid.NewGuid().ToString("N");
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, origin)
            VALUES (@id, @packageId, @version, @purl, @blobKey, @sizeBytes, @checksumSha256, @origin)
            """,
            new { id, packageId, version, purl, blobKey, sizeBytes, checksumSha256, origin });
        return id;
    }
}
