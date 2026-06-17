using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the Go module proxy surface (<c>/go/</c>).
///
/// Tests use the in-memory blob store and a WireMock upstream; the "golang" upstream URL
/// is seeded to MockUpstream by <see cref="DependablyFactory"/>. Each test targets a
/// distinct module path so there is no state bleed between them.
/// </summary>
[Trait("Category", "Integration")]
public sealed class GoControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public GoControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── .mod proxy fetch and cache ────────────────────────────────────────────

    /// <summary>
    /// GET /go/{module}/@v/{version}.mod on a cold cache fetches from upstream and returns
    /// the go.mod bytes. The response Content-Type must be text/plain; charset=utf-8.
    /// </summary>
    [Fact]
    public async Task GetMod_CacheMiss_FetchesFromUpstreamAndReturnsModFile()
    {
        const string module = "example.com/testmod";
        const string version = "v1.0.0";
        const string modContent = "module example.com/testmod\n\ngo 1.21\n";

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{module}/@v/{version}.mod")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain; charset=utf-8")
                .WithBody(modContent));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@v/{version}.mod");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("text/plain", resp.Content.Headers.ContentType?.MediaType ?? "");
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(modContent, body);
    }

    /// <summary>
    /// GET /go/{module}/@v/{version}.mod on a warm cache (blob already in blob store)
    /// returns the cached bytes without hitting upstream. X-Cache: HIT header is set.
    /// </summary>
    [Fact]
    public async Task GetMod_CacheHit_ServesCachedBytes()
    {
        const string module = "example.com/cachehitmod";
        const string version = "v2.0.0";
        const string modContent = "module example.com/cachehitmod\n\ngo 1.21\n";

        // Pre-populate the blob store directly so there is no upstream call.
        string orgId = await GetDefaultOrgIdAsync();
        string blobKey = Dependably.Storage.BlobKeys.Go(orgId, module, version, "mod");
        byte[] modBytes = Encoding.UTF8.GetBytes(modContent);
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(modBytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@v/{version}.mod");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("HIT", resp.Headers.GetValues("X-Cache").FirstOrDefault());
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(modContent, body);
    }

    // ── .info proxy fetch ─────────────────────────────────────────────────────

    /// <summary>
    /// GET /go/{module}/@v/{version}.info fetches from upstream and returns JSON.
    /// The Content-Type must be application/json.
    /// </summary>
    [Fact]
    public async Task GetInfo_CacheMiss_ReturnsJsonFromUpstream()
    {
        const string module = "example.com/infomod";
        const string version = "v1.0.0";
        const string infoJson = "{\"Version\":\"v1.0.0\",\"Time\":\"2024-01-15T10:00:00Z\"}";

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{module}/@v/{version}.info")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(infoJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@v/{version}.info");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("application/json", resp.Content.Headers.ContentType?.MediaType ?? "");
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("v1.0.0", doc.RootElement.GetProperty("Version").GetString());
    }

    // ── @v/list ───────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /go/{module}/@v/list returns an empty body when no versions are cached.
    /// </summary>
    [Fact]
    public async Task GetList_NoVersionsCached_ReturnsEmptyBody()
    {
        const string module = "example.com/listmod-empty";

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@v/list");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Empty(body.Trim());
    }

    /// <summary>
    /// GET /go/{module}/@v/list returns the versions recorded after a .zip proxy fetch.
    /// </summary>
    [Fact]
    public async Task GetList_AfterZipFetch_ReturnsVersion()
    {
        const string module = "example.com/listmod-populated";
        const string version = "v1.2.3";

        // Stub a zip response (minimal fake zip for the blob store).
        byte[] fakeZip = [0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{module}/@v/{version}.zip")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/zip")
                .WithBody(fakeZip));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Fetch the zip to seed the catalogue.
        var zipResp = await client.GetAsync($"/go/{module}/@v/{version}.zip");
        Assert.Equal(HttpStatusCode.OK, zipResp.StatusCode);

        // Now the list should include v1.2.3.
        var listResp = await client.GetAsync($"/go/{module}/@v/list");
        Assert.Equal(HttpStatusCode.OK, listResp.StatusCode);
        string body = await listResp.Content.ReadAsStringAsync();
        Assert.Contains(version, body);
    }

    // ── Cache-access recording ────────────────────────────────────────────────

    /// <summary>
    /// A .zip proxy fetch records the artefact in the shared cache index
    /// (<c>cache_artifact</c>) and the per-tenant access row (<c>tenant_artifact_access</c>),
    /// so the eviction pipeline and vulnerability-response query can see proxied Go modules.
    /// </summary>
    [Fact]
    public async Task GetZip_RecordsCacheArtifactAndTenantAccess()
    {
        const string module = "example.com/cachezipmod";
        const string version = "v4.5.6";

        byte[] fakeZip = [0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{module}/@v/{version}.zip")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/zip")
                .WithBody(fakeZip));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var zipResp = await client.GetAsync($"/go/{module}/@v/{version}.zip");
        Assert.Equal(HttpStatusCode.OK, zipResp.StatusCode);

        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services
            .GetRequiredService<Dependably.Infrastructure.IMetadataStore>()
            .OpenAsync();

        long artifactCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(conn,
            """
            SELECT COUNT(*) FROM cache_artifact
            WHERE ecosystem = 'golang' AND name = @module AND version = @version
            """,
            new { module, version });
        Assert.True(artifactCount > 0, "cache_artifact row should exist after a Go .zip proxy fetch.");

        long accessCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(conn,
            """
            SELECT taa.access_count
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE ca.ecosystem = 'golang' AND ca.name = @module AND ca.version = @version
              AND taa.org_id = @orgId
            """,
            new { module, version, orgId });
        Assert.True(accessCount >= 1, "tenant_artifact_access row should exist for the org.");
    }

    // ── @latest proxy ─────────────────────────────────────────────────────────

    /// <summary>
    /// GET /go/{module}/@latest when nothing is cached proxies upstream @latest.
    /// </summary>
    [Fact]
    public async Task GetLatest_NoCachedVersions_ProxiesUpstream()
    {
        const string module = "example.com/latestmod";
        const string latestJson = "{\"Version\":\"v1.3.0\",\"Time\":\"2024-06-01T00:00:00Z\",\"Origin\":null}";

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{module}/@latest")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(latestJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/{module}/@latest");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("application/json", resp.Content.Headers.ContentType?.MediaType ?? "");
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("v1.3.0", doc.RootElement.GetProperty("Version").GetString());
    }

    // ── Bang-encoding in routes ───────────────────────────────────────────────

    /// <summary>
    /// Module paths with uppercase letters are bang-encoded on the wire
    /// (<c>!a</c> → <c>A</c>). The controller must decode before looking up the blob key
    /// or calling upstream — upstream URL must be constructed with re-encoded form.
    /// </summary>
    [Fact]
    public async Task GetMod_BangEncodedModulePath_DecodesAndFetchesCorrectly()
    {
        // The "real" module name contains uppercase.
        const string decodedModule = "github.com/Azure/sdk-for-go";
        const string encodedModule = "github.com/!azure/sdk-for-go";
        const string version = "v1.0.0";
        const string modContent = "module github.com/Azure/sdk-for-go\n\ngo 1.21\n";

        // Upstream expects the bang-encoded path (as real proxy.golang.org does).
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{encodedModule}/@v/{version}.mod")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain; charset=utf-8")
                .WithBody(modContent));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Client sends bang-encoded path (as go toolchain does).
        var resp = await client.GetAsync($"/go/{encodedModule}/@v/{version}.mod");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(modContent, body);

        // The blob must be stored under the decoded module path.
        string orgId = await GetDefaultOrgIdAsync();
        string blobKey = Dependably.Storage.BlobKeys.Go(orgId, decodedModule, version, "mod");
        bool exists = await _factory.BlobStore.ExistsAsync(blobKey);
        Assert.True(exists, "Blob should be cached under the decoded module path.");
    }

    // ── Auth gate ─────────────────────────────────────────────────────────────

    /// <summary>
    /// When AnonymousPull is off (the default in tests), an unauthenticated GET returns 401.
    /// </summary>
    [Fact]
    public async Task GetMod_NoToken_Returns401WhenAnonymousPullOff()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/go/example.com/authtest/@v/v1.0.0.mod");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── sumdb passthrough ─────────────────────────────────────────────────────

    // The configured sumdb name (Go:SumDb) is the WireMock host; the go client requests
    // /go/sumdb/{name}/... so tests address the mock by its host.
    private string SumDbName => new Uri(_factory.MockUpstream.Urls[0]).Host;

    /// <summary>
    /// GET /go/sumdb/{configured-name}/supported returns 200 with an empty body — the capability
    /// probe that tells the go client the proxy proxies this checksum database. No upstream call.
    /// </summary>
    [Fact]
    public async Task GetSumdbSupported_ConfiguredName_Returns200EmptyBody()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}/supported");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Empty(body);
    }

    /// <summary>
    /// GET /go/sumdb/{unknown-name}/supported returns 404 so the go client falls back to
    /// verifying the checksum database directly. No upstream call is made.
    /// </summary>
    [Fact]
    public async Task GetSumdbSupported_UnknownName_Returns404()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/go/sumdb/other-sumdb.example.com/supported");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// A sumdb lookup path is proxied verbatim: the upstream status and body pass through
    /// untouched (the client verifies the transparency-log signatures itself).
    /// </summary>
    [Fact]
    public async Task GetSumdbLookup_ConfiguredName_ProxiesVerbatim()
    {
        const string lookupPath = "lookup/golang.org/x/text@v0.3.0";
        const string lookupBody =
            "golang.org/x/text v0.3.0 h1:abcdef\ngolang.org/x/text v0.3.0/go.mod h1:123456\n";

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{lookupPath}")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain; charset=utf-8")
                .WithBody(lookupBody));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/sumdb/{SumDbName}/{lookupPath}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Equal(lookupBody, body);
    }

    /// <summary>
    /// A fetch for an unknown sumdb name returns 404 without reaching upstream — the proxy never
    /// fetches a client-chosen host (SSRF guard).
    /// </summary>
    [Fact]
    public async Task GetSumdbLookup_UnknownName_Returns404WithoutUpstreamCall()
    {
        const string unknownName = "evil-sumdb.example.com";
        const string lookupPath = "lookup/example.com/mod@v1.0.0";

        // Stub the path on the mock; the unknown-name guard must short-circuit before any call,
        // so this stub must NOT be hit.
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{lookupPath}")
                    .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithBody("should-not-be-served"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/go/sumdb/{unknownName}/{lookupPath}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("should-not-be-served", body);
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services
            .GetRequiredService<Dependably.Infrastructure.IMetadataStore>()
            .OpenAsync();
        return await Dapper.SqlMapper.ExecuteScalarAsync<string>(conn,
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }
}
