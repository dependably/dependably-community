using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Covers <see cref="OciImageLicenseRecorder"/>: the two capture points that stamp the OCI
/// image-license columns on <c>oci_blobs</c>, the self-healing manifest-before-config race, the
/// index/multi-arch NULL rule, the per-org inserted-gating, and idempotence.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciImageLicenseRecorderTests : IAsyncLifetime
{
    private const string ManifestMediaType = "application/vnd.oci.image.manifest.v1+json";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobStore = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private OciImageLicenseRecorder _sut = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        var tiered = new TieredBlobStorage(_blobStore, _blobStore);
        _sut = new OciImageLicenseRecorder(_db, tiered, _clock, NullLogger<OciImageLicenseRecorder>.Instance);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── push-style: config already present → manifest capture stamps license ──

    [Fact]
    public async Task RecordManifest_ConfigPresent_StampsLicense()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-push-{Guid.NewGuid():N}");
        var (manifest, manifestDigest, configDigest) = await SeedImageAsync(orgId, "MIT", origin: "uploaded");

        await _sut.RecordManifestAsync(orgId, manifestDigest, manifest, default);

        var row = await ReadLicenseAsync(orgId, manifestDigest);
        Assert.Equal(configDigest, row.ConfigDigest);
        Assert.Equal("MIT", row.LicenseSpdx);
        Assert.NotNull(row.LicenseCheckedAt);
    }

    [Fact]
    public async Task RecordManifest_ConfigWithoutLabel_StampsNullLicenseButMarksChecked()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-nolabel-{Guid.NewGuid():N}");
        var (manifest, manifestDigest, _) = await SeedImageAsync(orgId, license: null, origin: "uploaded");

        await _sut.RecordManifestAsync(orgId, manifestDigest, manifest, default);

        var row = await ReadLicenseAsync(orgId, manifestDigest);
        Assert.Null(row.LicenseSpdx);
        Assert.NotNull(row.LicenseCheckedAt); // stamped so a label-less image is never reparsed
    }

    // ── proxy-style: manifest first (no config yet), then config arrives ──

    [Fact]
    public async Task ManifestFirstThenConfigArrival_StampsOnArrival()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-proxy-{Guid.NewGuid():N}");
        byte[] configBytes = ConfigJson("Apache-2.0");
        string configDigest = Digest(configBytes);
        byte[] manifest = ManifestJson(configDigest, configBytes.Length);
        string manifestDigest = Digest(manifest);

        // Manifest row exists but the config blob has NOT been fetched yet.
        await InsertBlobAsync(orgId, manifestDigest, ManifestMediaType, "proxy", storeBytes: null);

        await _sut.RecordManifestAsync(orgId, manifestDigest, manifest, default);

        // config_digest stamped, but license not yet (config absent).
        var afterManifest = await ReadLicenseAsync(orgId, manifestDigest);
        Assert.Equal(configDigest, afterManifest.ConfigDigest);
        Assert.Null(afterManifest.LicenseCheckedAt);

        // Config blob arrives in the cache and its DB row is inserted.
        string configBlobKey = BlobKeys.OciBlob("sha256", configDigest.Split(':')[1]);
        await _blobStore.PutAsync(configBlobKey, new MemoryStream(configBytes));
        await InsertBlobAsync(orgId, configDigest, "application/octet-stream", "proxy", storeBytes: null, blobKey: configBlobKey);

        await _sut.RecordConfigBlobArrivalAsync(orgId, configDigest, configBlobKey, default);

        var afterConfig = await ReadLicenseAsync(orgId, manifestDigest);
        Assert.Equal("Apache-2.0", afterConfig.LicenseSpdx);
        Assert.NotNull(afterConfig.LicenseCheckedAt);
    }

    [Fact]
    public async Task ConfigArrival_NoManifestAwaiting_NoOp()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-noawait-{Guid.NewGuid():N}");
        byte[] configBytes = ConfigJson("MIT");
        string configDigest = Digest(configBytes);
        string configBlobKey = BlobKeys.OciBlob("sha256", configDigest.Split(':')[1]);
        await _blobStore.PutAsync(configBlobKey, new MemoryStream(configBytes));
        await InsertBlobAsync(orgId, configDigest, "application/octet-stream", "proxy", storeBytes: null, blobKey: configBlobKey);

        // No manifest references this config → the indexed probe short-circuits, nothing stamped.
        await _sut.RecordConfigBlobArrivalAsync(orgId, configDigest, configBlobKey, default);

        var row = await ReadLicenseAsync(orgId, configDigest);
        Assert.Null(row.LicenseCheckedAt);
    }

    // ── index / multi-arch ──

    [Fact]
    public async Task RecordManifest_ImageIndex_LeavesAllColumnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-index-{Guid.NewGuid():N}");
        byte[] index = Encoding.UTF8.GetBytes("""
        {
          "schemaVersion": 2,
          "mediaType": "application/vnd.oci.image.index.v1+json",
          "manifests": [
            { "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
          ]
        }
        """);
        string indexDigest = Digest(index);
        await InsertBlobAsync(orgId, indexDigest, "application/vnd.oci.image.index.v1+json", "proxy", storeBytes: null);

        await _sut.RecordManifestAsync(orgId, indexDigest, index, default);

        var row = await ReadLicenseAsync(orgId, indexDigest);
        Assert.Null(row.ConfigDigest);
        Assert.Null(row.LicenseSpdx);
        Assert.Null(row.LicenseCheckedAt);
    }

    // ── per-org inserted-gating: a second org gets its own stamped row ──

    [Fact]
    public async Task SecondOrg_SharedConfig_StampsIndependently()
    {
        string orgA = await OrgSeeder.InsertAsync(_db, $"rec-orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_db, $"rec-orgB-{Guid.NewGuid():N}");
        var (manifestA, manifestDigest, configDigest) = await SeedImageAsync(orgA, "MIT", origin: "uploaded");
        await _sut.RecordManifestAsync(orgA, manifestDigest, manifestA, default);

        // Org B pulls the same manifest+config (own rows, same content-addressed blobs).
        string configBlobKey = BlobKeys.OciBlob("sha256", configDigest.Split(':')[1]);
        await InsertBlobAsync(orgB, configDigest, "application/octet-stream", "uploaded", storeBytes: null, blobKey: configBlobKey);
        await InsertBlobAsync(orgB, manifestDigest, ManifestMediaType, "uploaded", storeBytes: null);
        await _sut.RecordManifestAsync(orgB, manifestDigest, manifestA, default);

        Assert.Equal("MIT", (await ReadLicenseAsync(orgA, manifestDigest)).LicenseSpdx);
        Assert.Equal("MIT", (await ReadLicenseAsync(orgB, manifestDigest)).LicenseSpdx);
    }

    // ── idempotence: a completed stamp is never overwritten ──

    [Fact]
    public async Task RecordManifest_Rerun_DoesNotChangeCheckedAt()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"rec-idem-{Guid.NewGuid():N}");
        var (manifest, manifestDigest, _) = await SeedImageAsync(orgId, "MIT", origin: "uploaded");
        await _sut.RecordManifestAsync(orgId, manifestDigest, manifest, default);
        string? first = (await ReadLicenseAsync(orgId, manifestDigest)).LicenseCheckedAt;

        _clock.Advance(TimeSpan.FromHours(1));
        await _sut.RecordManifestAsync(orgId, manifestDigest, manifest, default);
        string? second = (await ReadLicenseAsync(orgId, manifestDigest)).LicenseCheckedAt;

        Assert.Equal(first, second); // license_checked_at IS NULL guard prevents a reparse
    }

    // ── helpers ──

    private async Task<(byte[] Manifest, string ManifestDigest, string ConfigDigest)> SeedImageAsync(
        string orgId, string? license, string origin)
    {
        byte[] configBytes = ConfigJson(license);
        string configDigest = Digest(configBytes);
        byte[] manifest = ManifestJson(configDigest, configBytes.Length);
        string manifestDigest = Digest(manifest);

        string configBlobKey = BlobKeys.OciBlob("sha256", configDigest.Split(':')[1]);
        await _blobStore.PutAsync(configBlobKey, new MemoryStream(configBytes));
        await InsertBlobAsync(orgId, configDigest, "application/octet-stream", origin, storeBytes: null, blobKey: configBlobKey);
        await InsertBlobAsync(orgId, manifestDigest, ManifestMediaType, origin, storeBytes: null);
        return (manifest, manifestDigest, configDigest);
    }

    private async Task InsertBlobAsync(
        string orgId, string digest, string mediaType, string origin, byte[]? storeBytes, string? blobKey = null)
    {
        blobKey ??= BlobKeys.OciBlob("sha256", digest.Split(':')[1]);
        if (storeBytes is not null)
        {
            await _blobStore.PutAsync(blobKey, new MemoryStream(storeBytes));
        }
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, 0, @blobKey, @origin, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            ON CONFLICT(digest, org_id) DO NOTHING
            """,
            new { digest, orgId, mediaType, blobKey, origin });
    }

    private async Task<LicenseRow> ReadLicenseAsync(string orgId, string digest)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<LicenseRow>(
            "SELECT config_digest AS ConfigDigest, license_spdx AS LicenseSpdx, " +
            "license_checked_at AS LicenseCheckedAt FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
    }

    private static byte[] ConfigJson(string? license)
    {
        string labels = license is null
            ? """{ "architecture": "amd64" }"""
            : $$"""{ "config": { "Labels": { "org.opencontainers.image.licenses": "{{license}}" } } }""";
        return Encoding.UTF8.GetBytes(labels);
    }

    private static byte[] ManifestJson(string configDigest, long configSize) =>
        Encoding.UTF8.GetBytes($$"""
        {
          "schemaVersion": 2,
          "mediaType": "{{ManifestMediaType}}",
          "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "{{configDigest}}",
            "size": {{configSize}}
          },
          "layers": []
        }
        """);

    private static string Digest(byte[] bytes) =>
        "sha256:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record LicenseRow(string? ConfigDigest, string? LicenseSpdx, string? LicenseCheckedAt);
}
