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

    /// <summary>
    /// sumdb paths return 404 (not implemented in MR1).
    /// </summary>
    [Fact]
    public async Task GetSumdb_Returns404()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/go/sumdb/sum.golang.org/lookup/golang.org/x/net@v0.10.0");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
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
