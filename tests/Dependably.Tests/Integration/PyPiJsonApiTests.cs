using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for the PyPI JSON API endpoints:
/// GET /pypi/{package}/json and GET /pypi/{package}/{version}/json.
///
/// Covers: hosted-package synthesis (releases map, sha256 digest, yanked flag),
/// versioned form, 404 for unknown package with no upstream, anonymous-pull gate
/// parity with the simple index, and upstream proxy pass-through.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiJsonApiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PyPiJsonApiTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgId()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetAnonymousPull(bool enabled)
    {
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task SetProxyPassthrough(bool enabled)
    {
        string orgId = await DefaultOrgId();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // ── Hosted package — unversioned form ────────────────────────────────────

    [Fact]
    public async Task PackageJson_HostedPackage_ReturnsJsonWithCorrectShape()
    {
        // Push a wheel and verify the JSON document has info, releases, and urls sections
        // with the correct fields derived from stored metadata.
        string name = $"jsontest{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);

        // Top-level sections present
        Assert.True(doc.RootElement.TryGetProperty("info", out var info));
        Assert.True(doc.RootElement.TryGetProperty("releases", out var releases));
        Assert.True(doc.RootElement.TryGetProperty("urls", out var urls));

        // info.version is the pushed version
        Assert.Equal("1.0.0", info.GetProperty("version").GetString());
        // info.name is the package name
        Assert.Equal(name, info.GetProperty("name").GetString());

        // releases["1.0.0"] is a non-empty array
        Assert.True(releases.TryGetProperty("1.0.0", out var vFiles));
        Assert.Equal(JsonValueKind.Array, vFiles.ValueKind);
        Assert.True(vFiles.GetArrayLength() > 0);

        // First file entry has filename and url
        var fileEntry = vFiles.EnumerateArray().First();
        string? filename = fileEntry.GetProperty("filename").GetString();
        string? url = fileEntry.GetProperty("url").GetString();
        Assert.NotNull(filename);
        Assert.NotNull(url);
        Assert.StartsWith("/packages/", url);

        // sha256 digest is present (stored at upload time)
        Assert.True(fileEntry.TryGetProperty("digests", out var digests));
        Assert.True(digests.TryGetProperty("sha256", out var sha256));
        Assert.False(string.IsNullOrEmpty(sha256.GetString()));

        // urls matches the files for the latest version
        Assert.Equal(JsonValueKind.Array, urls.ValueKind);
        Assert.True(urls.GetArrayLength() > 0);
    }

    [Fact]
    public async Task PackageJson_HostedPackage_YankedVersionFlaggedInReleases()
    {
        // Push a version then yank it — the releases entry must carry yanked=true.
        string name = $"yankjson{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "2.0.0");
        await _factory.SetVersionYanked("default", "pypi", name, "2.0.0", "security");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);

        var releases = doc.RootElement.GetProperty("releases");
        var files = releases.GetProperty("2.0.0");
        var entry = files.EnumerateArray().First();
        Assert.True(entry.GetProperty("yanked").GetBoolean());
    }

    // ── Versioned form ────────────────────────────────────────────────────────

    [Fact]
    public async Task PackageVersionJson_HostedPackage_ReturnsCorrectVersionInfo()
    {
        // Push two versions; the versioned endpoint must surface only the requested one
        // in `info.version` and `urls`.
        string name = $"verfixed{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");
        await _factory.PushPyPiPackage(name, "2.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/1.0.0/json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);

        // info.version must be the requested version
        Assert.Equal("1.0.0", doc.RootElement.GetProperty("info").GetProperty("version").GetString());

        // releases must contain both versions
        var releases = doc.RootElement.GetProperty("releases");
        Assert.True(releases.TryGetProperty("1.0.0", out _));
        Assert.True(releases.TryGetProperty("2.0.0", out _));

        // urls is the file list for 1.0.0
        var urls = doc.RootElement.GetProperty("urls");
        Assert.Equal(JsonValueKind.Array, urls.ValueKind);
        Assert.True(urls.GetArrayLength() > 0);
    }

    [Fact]
    public async Task PackageVersionJson_UnknownVersion_Returns404()
    {
        // Versioned endpoint for a version that doesn't exist → 404.
        string name = $"noverjson{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/9.9.9/json");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── 404 for unknown package with no upstream ──────────────────────────────

    [Fact]
    public async Task PackageJson_UnknownPackage_PassthroughDisabled_Returns404()
    {
        // Passthrough off and no local package → 404.
        await SetProxyPassthrough(false);
        try
        {
            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/pypi/totally-unknown-{Guid.NewGuid():N}/json");
            Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        }
        finally
        {
            await SetProxyPassthrough(true);
        }
    }

    [Fact]
    public async Task PackageJson_UnknownPackage_UpstreamReturns404_Returns404()
    {
        // Passthrough on but upstream also 404s → our endpoint 404s.
        string name = $"notexist{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/json");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Anonymous-pull gate ────────────────────────────────────────────────────

    [Fact]
    public async Task PackageJson_AnonymousPullDisabled_NoToken_Returns401()
    {
        // AnonymousPull=false and no credentials → 401 with WWW-Authenticate, same as
        // the simple index auth gate.
        string name = $"authjson{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "1.0.0");

        using var client = _factory.CreateClient();
        var resp = await client.GetAsync($"/pypi/{name}/json");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Basic", resp.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task PackageJson_AnonymousPullEnabled_NoToken_Returns200()
    {
        // AnonymousPull=true — the JSON endpoint is accessible without credentials.
        await SetAnonymousPull(true);
        try
        {
            string name = $"anonpull{Guid.NewGuid():N}"[..15].ToLowerInvariant();
            await _factory.PushPyPiPackage(name, "1.0.0");

            using var client = _factory.CreateClient();
            var resp = await client.GetAsync($"/pypi/{name}/json");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }
        finally
        {
            await SetAnonymousPull(false);
        }
    }

    // ── Upstream proxy passthrough ────────────────────────────────────────────

    [Fact]
    public async Task PackageJson_ProxyOnly_PassthroughEnabled_ReturnsUpstreamDocument()
    {
        // No hosted versions, passthrough enabled, upstream serves a JSON document →
        // the endpoint forwards the upstream JSON verbatim.
        string name = $"proxyjson{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string upstreamJson = $$"""
            {"info":{"name":"{{name}}","version":"3.0.0"},"releases":{"3.0.0":[]},"urls":[]}
            """;

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/json").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(name, doc.RootElement.GetProperty("info").GetProperty("name").GetString());
    }

    [Fact]
    public async Task PackageVersionJson_ProxyOnly_ForwardsVersionedUpstreamDocument()
    {
        // Versioned form also proxies upstream when no hosted versions exist.
        string name = $"proxyvjson{Guid.NewGuid():N}"[..15].ToLowerInvariant();
        string upstreamJson = $$"""
            {"info":{"name":"{{name}}","version":"5.0.0"},"releases":{"5.0.0":[]},"urls":[]}
            """;

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/5.0.0/json").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(upstreamJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/pypi/{name}/5.0.0/json");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal("5.0.0", doc.RootElement.GetProperty("info").GetProperty("version").GetString());
    }
}
