using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the proxy first-fetch upstream-latest seed: <see cref="ProxyVersionRecorder.RecordAsync"/>
/// resolves and records <c>packages.upstream_latest_version</c> the first time a package is proxied
/// (so its "Latest" indicator appears immediately), and skips the resolve once a baseline exists.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProxyVersionRecorderTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task RecordAsync_FirstFetch_SeedsUpstreamLatestWhenAbsent()
    {
        string orgId = await SeedOrgAsync();
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync("npm", orgId, "left-pad", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new UpstreamLatestVersion("9.9.9", null)));
        var recorder = BuildRecorder(resolver);
        string caId = await SeedCacheArtifactAsync(orgId, "left-pad", "1.0.0");

        await recorder.RecordAsync(await BuildRequestAsync(orgId, "left-pad", "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Equal("9.9.9", await ReadUpstreamLatestAsync(orgId, "left-pad"));
        await resolver.Received(1).ResolveAsync("npm", orgId, "left-pad", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RecordAsync_FirstFetch_SeedsUpstreamLatestPublishedAtWhenKnown()
    {
        string orgId = await SeedOrgAsync();
        var publishedAt = new DateTimeOffset(2024, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync("npm", orgId, "left-pad", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new UpstreamLatestVersion("9.9.9", publishedAt)));
        var recorder = BuildRecorder(resolver);
        string caId = await SeedCacheArtifactAsync(orgId, "left-pad", "1.0.0");

        await recorder.RecordAsync(await BuildRequestAsync(orgId, "left-pad", "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        var packages = new PackageRepository(_db);
        var pkg = await packages.GetByPurlNameAsync(orgId, "npm", "left-pad");
        Assert.Equal(publishedAt, pkg!.UpstreamLatestPublishedAt);
    }

    [Fact]
    public async Task RecordAsync_FirstFetch_SkipsResolveWhenBaselineExists()
    {
        string orgId = await SeedOrgAsync();
        // A prior pass already recorded a baseline; the daily refresh owns currency from here.
        await SeedPackageWithLatestAsync(orgId, "left-pad", "5.0.0");
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new UpstreamLatestVersion("9.9.9", null)));
        var recorder = BuildRecorder(resolver);
        string caId = await SeedCacheArtifactAsync(orgId, "left-pad", "1.1.0");

        await recorder.RecordAsync(await BuildRequestAsync(orgId, "left-pad", "1.1.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Equal("5.0.0", await ReadUpstreamLatestAsync(orgId, "left-pad"));
        await resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RecordAsync_FirstFetch_SeedsVersionsBehindOnTheCacheArtifactRow()
    {
        string orgId = await SeedOrgAsync();
        string caId = await SeedCacheArtifactAsync(orgId, "left-pad", "1.0.0");
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync("npm", orgId, "left-pad", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new UpstreamLatestVersion("9.9.9", null,
                StableVersionsDescending: new[] { "3.0.0", "2.0.0", "1.0.0" })));
        var recorder = BuildRecorder(resolver);

        await recorder.RecordAsync(
            await BuildRequestAsync(orgId, "left-pad", "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        await using var conn = await _db.OpenAsync();
        int? behind = await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal(2, behind); // 2.0.0 and 3.0.0 are newer than the held 1.0.0
    }

    /// <summary>
    /// Pins the manifest-extraction stream leak: <c>RecordProxyViaGlobalPlaneAsync</c> opens a
    /// fresh blob-store stream per fact-extraction pass (license, script-detection, npm
    /// manifest). Every stream <see cref="BlobHandle.OpenAsync"/> hands out must be disposed by
    /// the recorder — <see cref="InMemoryBlobStore"/>'s <c>MemoryStream</c> hides a leak here
    /// (nothing OS-visible to exhaust), so this asserts disposal directly via a tracking wrapper
    /// rather than relying on a real file descriptor running out.
    /// </summary>
    [Fact]
    public async Task RecordAsync_ProxyPath_WithExtractManifest_DisposesEveryOpenedStream()
    {
        string orgId = await SeedOrgAsync();
        string caId = await SeedCacheArtifactAsync(orgId, "left-pad", "1.0.0");
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        var recorder = BuildRecorder(resolver);

        byte[] bytes = "tarball-bytes"u8.ToArray();
        var openedStreams = new List<DisposalTrackingStream>();
        var blob = new BlobHandle("k", "sha", bytes.LongLength, _ =>
        {
            var tracked = new DisposalTrackingStream(new MemoryStream(bytes));
            openedStreams.Add(tracked);
            return Task.FromResult<Stream>(tracked);
        });
        var req = new ProxyVersionRequest(
            OrgId: orgId, Ecosystem: "npm", PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.0", Purl: "pkg:npm/left-pad@1.0.0",
            Sha256: "sha", File: "left-pad-1.0.0.tgz", Blob: blob, AuditActorId: null);

        await recorder.RecordAsync(
            req, extractLicenses: null, extractManifest: _ => "{\"dependencies\":{}}", cacheArtifactId: caId);

        Assert.NotEmpty(openedStreams);
        Assert.All(openedStreams, s => Assert.True(s.Disposed,
            "every stream BlobHandle.OpenAsync hands out during proxy first-fetch must be disposed"));
    }

    /// <summary>Stream wrapper that records whether it was disposed, sync or async.</summary>
    private sealed class DisposalTrackingStream(Stream inner) : Stream
    {
        public bool Disposed { get; private set; }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            Disposed = true;
            await inner.DisposeAsync();
            await base.DisposeAsync();
        }
    }

    private async Task<string> SeedCacheArtifactAsync(string orgId, string name, string version)
    {
        await using var conn = await _db.OpenAsync();
        string caId = Guid.NewGuid().ToString("N");
        string purl = $"pkg:npm/{name}@{version}";
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES (@id, 'npm', @name, @version, @filename, @blobKey, 'h', @purl)
            """,
            new { id = caId, name, version, filename = $"{name}-{version}.tgz", blobKey = $"proxy/{caId}/{name}-{version}.tgz", purl });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return caId;
    }

    private ProxyVersionRecorder BuildRecorder(IUpstreamLatestVersionResolver resolver) =>
        new(new PackageRepository(_db), new AuditRepository(_db),
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)), new CacheArtifactRepository(_db),
            resolver, NullLogger<ProxyVersionRecorder>.Instance);

    private async Task<ProxyVersionRequest> BuildRequestAsync(string orgId, string name, string version)
    {
        byte[] bytes = "tarball-bytes"u8.ToArray();
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        string key = BlobKeys.Proxy(sha);
        await _blobs.PutAsync(key, new MemoryStream(bytes));
        var blob = new BlobHandle(key, sha, bytes.LongLength,
            async ct => await _blobs.GetAsync(key, ct) ?? throw new InvalidOperationException("blob vanished"));
        return new ProxyVersionRequest(
            OrgId: orgId, Ecosystem: "npm", PackageName: name, PurlName: name,
            Version: version, Purl: $"pkg:npm/{name}@{version}",
            Sha256: sha, File: $"{name}-{version}.tgz", Blob: blob, AuditActorId: null);
    }

    private async Task<string> SeedOrgAsync()
    {
        string orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = $"org-{orgId[..6]}" });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@orgId)", new { orgId });
        return orgId;
    }

    private async Task SeedPackageWithLatestAsync(string orgId, string name, string latest)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, upstream_latest_version)
            VALUES (@id, @orgId, 'npm', @name, @name, 1, @latest)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, name, latest });
    }

    private async Task<string?> ReadUpstreamLatestAsync(string orgId, string name)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE org_id = @orgId AND purl_name = @name",
            new { orgId, name });
    }
}
