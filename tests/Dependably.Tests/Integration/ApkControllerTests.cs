using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the Alpine apk pull-through proxy surface (<c>/apk/</c>).
///
/// Tests use the in-memory blob store and a WireMock upstream; the "apk" upstream URL is
/// seeded to MockUpstream by <see cref="DependablyFactory"/>. Each test targets a distinct
/// release/repo/arch/file coordinate so there is no state bleed between them.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ApkControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ApkControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services
            .GetRequiredService<IMetadataStore>()
            .OpenAsync();
        return await SqlMapper.ExecuteScalarAsync<string>(conn,
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        string orgId = await GetDefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task ReserveApkNameAsync(string pattern)
    {
        string orgId = await GetDefaultOrgIdAsync();
        // Goes through the service (not a raw INSERT) so its 60s per-org list cache is
        // invalidated — a raw INSERT would leave a stale cached (pre-insert) list in place for
        // any org whose reserved-namespace list another test already warmed in this shared fixture.
        await _factory.Services.GetRequiredService<Dependably.Protocol.ReservedNamespaceService>()
            .AddAsync(orgId, "apk", pattern, createdBy: null);
    }

    private static int UpstreamCallCount(DependablyFactory f, string path) =>
        f.MockUpstream.LogEntries.Count(e =>
            string.Equals(e.RequestMessage?.Path, path, StringComparison.OrdinalIgnoreCase));

    private HttpClient CreateClientWithBasicUserinfo(string token)
    {
        var client = _factory.CreateClient();
        string basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"ci:{token}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basic);
        return client;
    }

    // ── .apk package: cache miss / hit ───────────────────────────────────────

    [Fact]
    public async Task GetPackage_CacheMiss_FetchesFromUpstream_RecordsGlobalFactsAndPurl()
    {
        const string release = "v3.22";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "curl-8.9.0-r0.apk";
        byte[] apkBytes = "fake-apk-bytes"u8.ToArray();

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(apkBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("MISS", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        byte[] body = await resp.Content.ReadAsByteArrayAsync();
        Assert.Equal(apkBytes, body);

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? purl = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT purl FROM cache_artifact
            WHERE ecosystem = 'apk' AND name = 'curl' AND version = '8.9.0-r0'
            """);
        Assert.Equal("pkg:apk/alpine/curl@8.9.0-r0?arch=x86_64", purl);

        // TOFU: the observed SHA-256 lands as an upstream-integrity fact, not a verified checksum.
        string? integrityAlgo = await conn.ExecuteScalarAsync<string?>(
            "SELECT upstream_integrity_algorithm FROM cache_artifact WHERE ecosystem = 'apk' AND name = 'curl'");
        Assert.Equal("sha256", integrityAlgo);
    }

    [Fact]
    public async Task GetPackage_CacheHit_ServesCachedBytesWithoutContactingUpstream()
    {
        const string release = "v3.22";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "busybox-static-1.36.1-r2.apk";
        byte[] apkBytes = "cached-apk-bytes"u8.ToArray();

        string orgId = await GetDefaultOrgIdAsync();
        string blobKey = BlobKeys.Apk(orgId, release, repo, arch, file);
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(apkBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        byte[] body = await resp.Content.ReadAsByteArrayAsync();
        Assert.Equal(apkBytes, body);
        Assert.Equal(0, UpstreamCallCount(_factory, $"/{release}/{repo}/{arch}/{file}"));
    }

    // ── mixed outcome: one package 404s and negative-caches, a sibling package succeeds ──

    [Fact]
    public async Task GetPackage_MixedBatch_OneMissingOneServed_MissingOneNegativelyCaches()
    {
        const string release = "v3.22";
        const string repo = "community";
        const string arch = "aarch64";
        const string missingFile = "does-not-exist-1.0.0-r0.apk";
        const string presentFile = "libssl3-3.3.1-r1.apk";
        byte[] apkBytes = "present-bytes"u8.ToArray();

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{missingFile}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{presentFile}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(apkBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // The missing package 404s...
        var missResp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{missingFile}");
        Assert.Equal(HttpStatusCode.NotFound, missResp.StatusCode);

        // ...while its sibling in the same repo/arch succeeds normally.
        var okResp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{presentFile}");
        Assert.Equal(HttpStatusCode.OK, okResp.StatusCode);
        Assert.Equal(apkBytes, await okResp.Content.ReadAsByteArrayAsync());

        // A second request for the missing package must hit the negative cache — no second
        // upstream call for the same coordinate.
        var missAgainResp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{missingFile}");
        Assert.Equal(HttpStatusCode.NotFound, missAgainResp.StatusCode);
        Assert.Equal(1, UpstreamCallCount(_factory, $"/{release}/{repo}/{arch}/{missingFile}"));
    }

    // ── reserved namespace ────────────────────────────────────────────────────

    [Fact]
    public async Task GetPackage_ReservedName_ReturnsNotFoundWithoutContactingUpstream()
    {
        const string release = "v3.22";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "acme-internal-1.0.0-r0.apk";

        await ReserveApkNameAsync("acme-internal");

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody("should-not-be-served"u8.ToArray()));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(0, UpstreamCallCount(_factory, $"/{release}/{repo}/{arch}/{file}"));
    }

    // ── auth ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetPackage_AnonymousPullOff_NoToken_Returns401Basic()
    {
        await SetAnonymousPullAsync(false);
        try
        {
            using var client = _factory.CreateClient();
            var resp = await client.GetAsync("/apk/v3.22/main/x86_64/curl-8.9.0-r0.apk");

            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            Assert.Contains("Basic", resp.Headers.WwwAuthenticate.Select(h => h.Scheme));
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task GetPackage_BasicAuthUserinfoStyle_Succeeds()
    {
        const string release = "v3.22";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "userinfo-test-1.0.0-r0.apk";
        byte[] apkBytes = "userinfo-auth-bytes"u8.ToArray();

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(apkBytes));

        await SetAnonymousPullAsync(false);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = CreateClientWithBasicUserinfo(token);

            // apk clients authenticate via https://user:token@host userinfo, which the HTTP
            // client layer translates into a Basic Authorization header — the same header
            // TokenAuthExtensions resolves for PyPI/NuGet.
            var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal(apkBytes, await resp.Content.ReadAsByteArrayAsync());
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── never-500 on a non-matching filename ─────────────────────────────────

    [Fact]
    public async Task GetPackage_NonMatchingFilename_StillProxiesWithoutError_NoGlobalPlaneRecording()
    {
        const string release = "v3.22";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "not-a-nevra-shaped-name.apk"; // no "-r{digits}" release segment
        byte[] apkBytes = "opaque-bytes"u8.ToArray();

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK).WithBody(apkBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(apkBytes, await resp.Content.ReadAsByteArrayAsync());

        // No name/version to key a cache_artifact coordinate on — nothing recorded.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'apk' AND filename LIKE @f",
            new { f = $"%{file}" });
        Assert.Equal(0, count);
    }

    // ── APKINDEX / index-adjacent passthrough ────────────────────────────────

    [Fact]
    public async Task GetIndex_ApkIndex_FetchesFromUpstreamAndCaches_SingleUpstreamCallOnRepeat()
    {
        const string release = "edge";
        const string repo = "main";
        const string arch = "x86_64";
        const string file = "APKINDEX.tar.gz";
        byte[] indexBytes = "fake-index-bytes"u8.ToArray();

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("ETag", "\"abc123\"")
                .WithBody(indexBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var first = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(indexBytes, await first.Content.ReadAsByteArrayAsync());

        var second = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(indexBytes, await second.Content.ReadAsByteArrayAsync());

        // Short-TTL memory cache: a repeat request within the TTL window is served without a
        // second upstream round-trip (single-flight passthrough, mirrors RPM's repomd cache).
        Assert.Equal(1, UpstreamCallCount(_factory, $"/{release}/{repo}/{arch}/{file}"));
    }

    [Fact]
    public async Task GetIndex_UpstreamMissing_ReturnsNotFound()
    {
        const string release = "v3.22";
        const string repo = "testing";
        const string arch = "armv7";
        const string file = "APKINDEX.tar.gz";

        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{release}/{repo}/{arch}/{file}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{file}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
