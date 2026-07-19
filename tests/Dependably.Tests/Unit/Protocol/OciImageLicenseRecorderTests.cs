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
        _sut = new OciImageLicenseRecorder(_db, tiered, _clock, NullLogger<OciImageLicenseRecorder>.Instance,
                new LicenseRepository(_db, _clock, TestNormalizers.License(_db)));
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

    // ── Projection onto the shared plane ─────────────────────────────────────────
    // The license is captured on the oci_blobs manifest row before any catalogue row exists, so it
    // is projected afterwards onto whichever row the image cast. Writing it to the shared
    // package_version_licenses table is what lets every license reader — the package-detail page,
    // the license-risk tile and its drill-down, the review queue — see an image's license through
    // the same query it already uses for every other ecosystem.

    [Fact]
    public async Task ProjectLicenseToCatalog_PushedImage_WritesTheLicenseOntoItsPackageVersion()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"proj-push-{Guid.NewGuid():N}");
        const string digest = "sha256:aaaa111111111111111111111111111111111111111111111111111111111111";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, license_spdx) " +
            "VALUES (@digest, @orgId, 'oci/sha256/aaaa', 10, 'application/vnd.oci.image.manifest.v1+json', 'MIT')",
            new { digest, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pp', @orgId, 'oci', 'library/nginx', 'library/nginx', 0)",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('vp', 'pp', @digest, 'pkg:oci/nginx@' || @digest, 'oci/sha256/aaaa', 'uploaded')",
            new { digest });

        await _sut.ProjectLicenseToCatalogAsync(orgId, digest, CancellationToken.None);

        string? spdx = await conn.ExecuteScalarAsync<string?>(
            "SELECT license_spdx FROM package_version_licenses WHERE package_version_id = 'vp'");
        Assert.Equal("MIT", spdx);
    }

    [Fact]
    public async Task ProjectLicenseToCatalog_ProxiedImage_WritesTheLicenseOntoItsCacheArtifact()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"proj-pull-{Guid.NewGuid():N}");
        const string digest = "sha256:bbbb222222222222222222222222222222222222222222222222222222222222";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, license_spdx) " +
            "VALUES (@digest, @orgId, 'oci/sha256/bbbb', 10, 'application/vnd.oci.image.manifest.v1+json', 'Apache-2.0')",
            new { digest, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('cap', 'oci', 'library/alpine', @digest, 'manifest', 'oci/sha256/bbbb', 'bbbb')",
            new { digest });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, 'cap')",
            new { orgId });

        await _sut.ProjectLicenseToCatalogAsync(orgId, digest, CancellationToken.None);

        string? spdx = await conn.ExecuteScalarAsync<string?>(
            "SELECT license_spdx FROM package_version_licenses WHERE cache_artifact_id = 'cap'");
        Assert.Equal("Apache-2.0", spdx);
    }

    [Fact]
    public async Task ProjectLicenseToCatalog_IsIdempotent_AndNoOpsWithNoCapturedLicense()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"proj-idem-{Guid.NewGuid():N}");
        const string licensed = "sha256:cccc333333333333333333333333333333333333333333333333333333333333";
        const string unlicensed = "sha256:dddd444444444444444444444444444444444444444444444444444444444444";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, license_spdx) VALUES
              (@licensed,   @orgId, 'oci/sha256/cccc', 10, 'application/vnd.oci.image.manifest.v1+json', 'MIT'),
              (@unlicensed, @orgId, 'oci/sha256/dddd', 10, 'application/vnd.oci.image.manifest.v1+json', NULL)
            """,
            new { licensed, unlicensed, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('pl', @orgId, 'oci', 'library/lic', 'library/lic', 0), " +
            "('pu', @orgId, 'oci', 'library/unlic', 'library/unlic', 0)",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES " +
            "('vl', 'pl', @licensed,   'pkg:oci/lic@x',   'oci/sha256/cccc', 'uploaded'), " +
            "('vu', 'pu', @unlicensed, 'pkg:oci/unlic@y', 'oci/sha256/dddd', 'uploaded')",
            new { licensed, unlicensed });

        // A re-push or a tag-TTL revalidation runs the projection again; it must not duplicate.
        await _sut.ProjectLicenseToCatalogAsync(orgId, licensed, CancellationToken.None);
        await _sut.ProjectLicenseToCatalogAsync(orgId, licensed, CancellationToken.None);
        await _sut.ProjectLicenseToCatalogAsync(orgId, unlicensed, CancellationToken.None);

        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE package_version_id = 'vl'"));
        // An image whose config carries no licenses label writes nothing at all — it stays honestly
        // license-unknown rather than acquiring an empty row.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE package_version_id = 'vu'"));
    }

    [Fact]
    public async Task ProjectedLicense_IsVisibleThroughTheLookupsThePackageDetailPageUses()
    {
        // OrgController's per-version license projection reads GetSpdxForVersionsAsync for uploaded
        // rows and GetSpdxForCacheArtifactsAsync for proxied ones — both keyed on
        // package_version_licenses. Once an image's license is a row in that table, the detail page
        // renders it with no OCI-specific code of its own, which is the whole point of projecting it.
        string orgId = await OrgSeeder.InsertAsync(_db, $"proj-detail-{Guid.NewGuid():N}");
        const string pushed = "sha256:eeee555555555555555555555555555555555555555555555555555555555555";
        const string pulled = "sha256:ffff666666666666666666666666666666666666666666666666666666666666";

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type, license_spdx) VALUES
              (@pushed, @orgId, 'oci/sha256/eeee', 10, 'application/vnd.oci.image.manifest.v1+json', 'MIT'),
              (@pulled, @orgId, 'oci/sha256/ffff', 10, 'application/vnd.oci.image.manifest.v1+json', 'Apache-2.0')
            """,
            new { pushed, pulled, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pd', @orgId, 'oci', 'library/nginx', 'library/nginx', 0)",
            new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) " +
            "VALUES ('vd', 'pd', @pushed, 'pkg:oci/nginx@x', 'oci/sha256/eeee', 'uploaded')",
            new { pushed });
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('cad', 'oci', 'library/alpine', @pulled, 'manifest', 'oci/sha256/ffff', 'ffff')",
            new { pulled });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, 'cad')",
            new { orgId });

        await _sut.ProjectLicenseToCatalogAsync(orgId, pushed, CancellationToken.None);
        await _sut.ProjectLicenseToCatalogAsync(orgId, pulled, CancellationToken.None);

        var licenses = new LicenseRepository(_db, _clock, TestNormalizers.License(_db));
        var uploaded = await licenses.GetSpdxForVersionsAsync(["vd"]);
        var proxied = await licenses.GetSpdxForCacheArtifactsAsync(["cad"]);

        Assert.Equal(["MIT"], uploaded["vd"]);
        Assert.Equal(["Apache-2.0"], proxied["cad"]);
    }

    private sealed record LicenseRow(string? ConfigDigest, string? LicenseSpdx, string? LicenseCheckedAt);
}
