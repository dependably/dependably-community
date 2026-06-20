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
            .Returns(Task.FromResult<string?>("9.9.9"));
        var recorder = BuildRecorder(resolver);

        await recorder.RecordAsync(await BuildRequestAsync(orgId, "left-pad", "1.0.0"), extractLicenses: null);

        Assert.Equal("9.9.9", await ReadUpstreamLatestAsync(orgId, "left-pad"));
        await resolver.Received(1).ResolveAsync("npm", orgId, "left-pad", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RecordAsync_FirstFetch_SkipsResolveWhenBaselineExists()
    {
        string orgId = await SeedOrgAsync();
        // A prior pass already recorded a baseline; the daily refresh owns currency from here.
        await SeedPackageWithLatestAsync(orgId, "left-pad", "5.0.0");
        var resolver = Substitute.For<IUpstreamLatestVersionResolver>();
        resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("9.9.9"));
        var recorder = BuildRecorder(resolver);

        await recorder.RecordAsync(await BuildRequestAsync(orgId, "left-pad", "1.1.0"), extractLicenses: null);

        Assert.Equal("5.0.0", await ReadUpstreamLatestAsync(orgId, "left-pad"));
        await resolver.DidNotReceive().ResolveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    private ProxyVersionRecorder BuildRecorder(IUpstreamLatestVersionResolver resolver) =>
        new(new PackageRepository(_db), new AuditRepository(_db),
            new LicenseRepository(_db, TimeProvider.System), new CacheArtifactRepository(_db),
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
            Sha256: sha, File: $"{name}-{version}.tgz", Blob: blob, UserId: null);
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
