using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for the storage-quota gate on OCI blob finalize and manifest push paths.
///
/// Covers:
/// - Blob finalize returns QuotaExceeded when the tenant's storage ceiling would be
///   breached; the quota counter stays accurate (no increment on rejection).
/// - Manifest store returns QuotaExceeded when the manifest would breach the ceiling.
/// - Both succeed when the quota is unset (unlimited).
/// - Mixed partial-failure: the first blob fits under the cap, the second is rejected
///   (each individually fits, but together they would exceed the cap). Exactly one
///   succeeds and the quota counter reflects only the accepted blob.
/// - Counter is released when a blob finalize fails after the reservation (blob write
///   simulation via ThrowOnPutBlobStore) so the counter stays accurate on retries.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciStorageQuotaTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly InMemoryBlobStore _cache = new();

    private OrgRepository _orgs = null!;
    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, 'acme')",
            new { id = _orgId });
        _orgs = new OrgRepository(_db);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ───────────────────────────────────────────────────────────────

    private OciUploadService BuildService(IBlobStore? registry = null)
    {
        var tiered = new TieredBlobStorage(_cache, registry ?? _registry);
        var cfg = new ConfigurationBuilder().Build();
        // Unlimited disk (floor = 0 opt-out) so quota tests focus on storage accounting.
        var stagingOptions = new StagingOptions(Path.GetTempPath(), FloorBytes: 0);
        return new OciUploadService(new OciUploadService.Dependencies(
            _db, tiered, _orgs, new UnlimitedDisk(), stagingOptions, cfg,
            NullLogger<OciUploadService>.Instance,
            TimeProvider.System));
    }

    private async Task<OciUploadSession> StartSessionAsync(OciUploadService svc, string repo = "team/app")
        => await svc.StartUploadAsync(_orgId, repo, default);

    private static byte[] RandomBytes(int n)
    {
        byte[] b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static string DigestOf(byte[] bytes)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // Appends bytes to the session by writing to its staging file directly, then calls
    // FinalizeBlobAsync with the correct digest.
    private async Task<OciBlobFinalizeResult> FinalizeAsync(OciUploadService svc, byte[] bytes, string? digestOverride = null)
    {
        var session = await StartSessionAsync(svc);
        // Write bytes to staging file via AppendChunkAsync
        await svc.AppendChunkAsync(_orgId, session, new MemoryStream(bytes), default);
        string digest = digestOverride ?? DigestOf(bytes);
        return await svc.FinalizeBlobAsync(_orgId, session, digest, default);
    }

    // Builds a minimal valid OCI manifest referencing known blobs that have already been
    // pushed via FinalizeBlobAsync so StoreManifestAsync's BlobExistsAsync check passes.
    private static byte[] BuildManifest(string configDigest, long configSize, string layerDigest, long layerSize)
    {
        const string mediaType = "application/vnd.oci.image.manifest.v1+json";
        string json = $$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{mediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": [
            {
              "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
              "digest": "{{layerDigest}}",
              "size": {{layerSize}}
            }
          ]
        }
        """;
        return Encoding.UTF8.GetBytes(json);
    }

    private async Task<long> ReadStorageUsedBytes()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COALESCE(storage_used_bytes, 0) FROM org_settings WHERE org_id = @orgId",
            new { orgId = _orgId });
    }

    // ── Blob finalize quota tests ─────────────────────────────────────────────

    [Fact]
    public async Task BlobFinalize_UnderQuota_Succeeds()
    {
        await _orgs.SetStorageQuotaBytesAsync(_orgId, 10_000);
        var svc = BuildService();
        byte[] blob = RandomBytes(512);

        var result = await FinalizeAsync(svc, blob);

        Assert.Equal(OciFinalizeStatus.Ok, result.Status);
    }

    [Fact]
    public async Task BlobFinalize_ExceedsQuota_ReturnsQuotaExceeded()
    {
        await _orgs.SetStorageQuotaBytesAsync(_orgId, 100); // tiny cap
        var svc = BuildService();
        byte[] blob = RandomBytes(512); // 512 > 100

        var result = await FinalizeAsync(svc, blob);

        Assert.Equal(OciFinalizeStatus.QuotaExceeded, result.Status);
        // Counter must not have been incremented on rejection.
        long counter = await ReadStorageUsedBytes();
        Assert.Equal(0, counter);
    }

    [Fact]
    public async Task BlobFinalize_NoQuotaSet_AlwaysSucceeds()
    {
        // No quota → unlimited; large blob must pass.
        var svc = BuildService();
        byte[] blob = RandomBytes(1024 * 1024); // 1 MiB

        var result = await FinalizeAsync(svc, blob);

        Assert.Equal(OciFinalizeStatus.Ok, result.Status);
    }

    // ── Manifest store quota tests ────────────────────────────────────────────

    [Fact]
    public async Task ManifestStore_ExceedsQuota_ReturnsQuotaExceeded()
    {
        // Push a config and layer blob successfully, then set a tight quota so the manifest
        // itself (which is also stored as a blob) would breach the ceiling.
        var svc = BuildService();
        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = RandomBytes(64);

        var configResult = await FinalizeAsync(svc, configBytes);
        var layerResult = await FinalizeAsync(svc, layerBytes);
        Assert.Equal(OciFinalizeStatus.Ok, configResult.Status);
        Assert.Equal(OciFinalizeStatus.Ok, layerResult.Status);

        // Set quota just below the current usage + manifest size.
        long usedSoFar = await ReadStorageUsedBytes();
        await _orgs.SetStorageQuotaBytesAsync(_orgId, usedSoFar); // no room for the manifest

        byte[] manifest = BuildManifest(configResult.Digest!, configBytes.Length, layerResult.Digest!, layerBytes.Length);
        var storeResult = await svc.StoreManifestAsync(
            _orgId, "team/app", "1.0.0", manifest,
            "application/vnd.oci.image.manifest.v1+json", default);

        Assert.Equal(OciManifestStatus.QuotaExceeded, storeResult.Status);
        // Counter must not have increased beyond usedSoFar.
        long counterAfter = await ReadStorageUsedBytes();
        Assert.Equal(usedSoFar, counterAfter);
    }

    [Fact]
    public async Task ManifestStore_UnderQuota_Succeeds()
    {
        var svc = BuildService();
        byte[] configBytes = Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux"}""");
        byte[] layerBytes = RandomBytes(64);

        var configResult = await FinalizeAsync(svc, configBytes);
        var layerResult = await FinalizeAsync(svc, layerBytes);

        // Set ample quota.
        await _orgs.SetStorageQuotaBytesAsync(_orgId, 1_000_000);

        byte[] manifest = BuildManifest(configResult.Digest!, configBytes.Length, layerResult.Digest!, layerBytes.Length);
        var storeResult = await svc.StoreManifestAsync(
            _orgId, "team/app", "1.0.0", manifest,
            "application/vnd.oci.image.manifest.v1+json", default);

        Assert.Equal(OciManifestStatus.Ok, storeResult.Status);
    }

    // ── Mixed partial-failure (house rule) ────────────────────────────────────

    [Fact]
    public async Task BlobFinalize_MixedScenario_FirstFitsSecondRejected_CounterAccurate()
    {
        // Cap: 800 bytes. First blob = 500 bytes (fits). Second blob = 400 bytes (together
        // would be 900 > 800 → rejected). The quota counter must reflect only the 500 bytes
        // of the accepted blob; the rejected blob must not inflate it.
        await _orgs.SetStorageQuotaBytesAsync(_orgId, 800);
        var svc = BuildService();

        byte[] blob1 = RandomBytes(500);
        byte[] blob2 = RandomBytes(400);

        var result1 = await FinalizeAsync(svc, blob1);
        Assert.Equal(OciFinalizeStatus.Ok, result1.Status);

        var result2 = await FinalizeAsync(svc, blob2);
        Assert.Equal(OciFinalizeStatus.QuotaExceeded, result2.Status);

        // Counter must equal exactly the first blob's size.
        long counter = await ReadStorageUsedBytes();
        Assert.Equal(500, counter);
    }

    // ── Counter release on blob write failure ─────────────────────────────────

    [Fact]
    public async Task BlobFinalize_WriteFailureAfterReservation_ReleasesCounter()
    {
        // Set a generous quota and make one successful blob push (300 bytes). Then attempt a
        // second push using a registry that throws on PutAsync to simulate a blob-write fault.
        // The quota counter must be back at 300 after the failure — not 700 — so a retry fits.
        await _orgs.SetStorageQuotaBytesAsync(_orgId, 2_000);
        var svc = BuildService();

        byte[] blob1 = RandomBytes(300);
        var result1 = await FinalizeAsync(svc, blob1);
        Assert.Equal(OciFinalizeStatus.Ok, result1.Status);

        long counterAfterFirst = await ReadStorageUsedBytes();
        Assert.Equal(300, counterAfterFirst);

        // Wire a throwing registry to simulate a blob-write fault on the second push.
        var throwingRegistry = new ThrowOnPutBlobStore(_registry);
        var failingSvc = BuildService(throwingRegistry);

        byte[] blob2 = RandomBytes(400);
        await Assert.ThrowsAnyAsync<Exception>(() => FinalizeAsync(failingSvc, blob2));

        // Counter must be back at 300 (not 700) after the aborted reservation.
        long counterAfterFailure = await ReadStorageUsedBytes();
        Assert.Equal(300, counterAfterFailure);
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    private sealed class ThrowOnPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        public ThrowOnPutBlobStore(IBlobStore inner) => _inner = inner;

        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
            => throw new InvalidOperationException("simulated blob write failure");

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => _inner.GetAsync(key, ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => _inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default)
            => _inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => _inner.GetTotalSizeAsync(ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}

/// <summary>Unlimited disk stub — floor check always passes.</summary>
file sealed class UnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
