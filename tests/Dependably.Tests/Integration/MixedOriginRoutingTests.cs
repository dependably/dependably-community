using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// Mixed-origin routing: a package name is a namespace that can hold both privately uploaded
/// versions and proxy-fetched/upstream versions. Uploading one private build must not lock
/// the rest of the namespace out of proxy passthrough.
///
/// Per memory feedback_per_version_origin_routing.md and feedback_test_partial_failure_scenarios.md,
/// these tests exercise the "some uploaded, some proxy, request a third uncached upstream version"
/// scenario in one flow per ecosystem.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MixedOriginRoutingTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public MixedOriginRoutingTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── NuGet: index merges upstream even when a hosted version exists ─────────

    [Fact]
    public async Task NuGet_Index_HostedNamespace_StillMergesUpstreamVersions()
    {
        var id = $"mixednuget{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        // Push a private 99.0.0 — this flips packages.is_proxy to false.
        await _factory.PushNuGetPackage(id, "99.0.0");

        // Stub upstream flatcontainer to return public versions for this name.
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("{\"versions\":[\"1.0.0\",\"2.0.0\"]}"));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetString()).ToHashSet();

        Assert.Contains("99.0.0", versions);
        Assert.Contains("1.0.0", versions);
        Assert.Contains("2.0.0", versions);
    }

    [Fact]
    public async Task NuGet_Index_UpstreamFailure_SetsXUpstreamStatusErrorHeader()
    {
        var id = $"upstreamerr{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("error", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());
    }

    // ── NuGet: download routes by version origin, not package flag ─────────────

    [Fact]
    public async Task NuGet_Download_UncachedUpstreamVersion_HostedNamespace_ProxyFetches()
    {
        var id = $"mixeddl{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "99.0.0");

        // Build a valid .nupkg for the upstream version so the proxy-fetch path can verify
        // checksums and produce a sane DB row.
        var (upstreamBytes, _) = NuGetFixtures.BuildNupkg(id, "1.2.3");
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/1.2.3/{id}.1.2.3.nupkg")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(upstreamBytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Despite packages.is_proxy=false (private upload exists), the public version is
        // still proxy-fetchable because routing now branches on per-version origin.
        var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/1.2.3/{id}.1.2.3.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task NuGet_Download_PrivateVersion_StillRequiresAuth()
    {
        var id = $"privatedl{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Anonymous request for the private version must still 401 — per-version routing
        // doesn't loosen the hosted-version auth requirement.
        using var anon = _factory.CreateClient();
        var resp = await anon.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── PyPi: simple index merges upstream + local ─────────────────────────────

    [Fact]
    public async Task PyPi_SimpleIndex_HostedNamespace_StillMergesUpstreamVersions()
    {
        var name = $"mixedpypi{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "99.0.0");

        var upstreamHtml = $"""
            <!DOCTYPE html>
            <html><body>
            <a href="https://files.pythonhosted.org/packages/aa/bb/{name}-1.0.0.tar.gz#sha256=cafe">{name}-1.0.0.tar.gz</a><br/>
            </body></html>
            """;

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/simple/{name}/")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html").WithBody(upstreamHtml));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains($"{name}-1.0.0.tar.gz", html);
        // Local 99.0.0 wheel filename pattern: {name_underscored}-99.0.0-py3-none-any.whl
        var underscored = name.Replace('-', '_');
        Assert.Contains($"{underscored}-99.0.0-py3-none-any.whl", html);
    }

    // ── Npm: packument merges upstream + local ─────────────────────────────────

    [Fact]
    public async Task Npm_Packument_HostedNamespace_StillMergesUpstreamVersions()
    {
        var name = $"mixednpm{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "99.0.0");

        var upstreamJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"1.0.0"},
          "versions": {
            "1.0.0": {
              "name": "{{name}}",
              "version": "1.0.0",
              "dist": {"tarball":"https://registry.npmjs.org/{{name}}/-/{{name}}-1.0.0.tgz","shasum":"deadbeef"}
            }
          }
        }
        """;

        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/{name}")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(upstreamJson));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var versions = doc.RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty("1.0.0", out _), "upstream version should be present");
        Assert.True(versions.TryGetProperty("99.0.0", out _), "uploaded local version should be merged in");
    }

    // ── NuGet: mixed origin in one flow ─────────────────────────────────────────

    [Fact]
    public async Task NuGet_MixedOrigin_PrivateAndProxiedVersionsCoexistOnSameName()
    {
        // Scenario from the failure report: a tenant uploaded a private version of a name
        // (origin='uploaded'), then later wants to proxy-fetch a different upstream version.
        // The proxy-fetched version is anonymously readable; the uploaded one still requires
        // auth. Both live under the same packages.id row.
        var id = $"coexist{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "99.0.0");

        // Mock upstream's nupkg for 1.0.0 so the proxy-fetch leg actually caches a row.
        var (nupkg100, _) = NuGetFixtures.BuildNupkg(id, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(nupkg100));

        // First fetch primes the cache: authenticated request for 1.0.0 succeeds and writes
        // a package_versions row with origin='proxy'.
        var token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var primeResp = await authClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // Confirm the DB has mixed origins on the same packages.id.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var origins = (await conn.QueryAsync<(string Version, string Origin)>(
            """
            SELECT pv.version, pv.origin
            FROM package_versions pv JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem='nuget' AND p.purl_name=@id
            """,
            new { id })).ToDictionary(r => r.Version, r => r.Origin);
        Assert.Equal("uploaded", origins["99.0.0"]);
        Assert.Equal("proxy", origins["1.0.0"]);

        // Now: anon request for the proxy version should succeed (cache hit, no auth required).
        using var anonClient = _factory.CreateClient();
        var anonProxyResp = await anonClient.GetAsync($"/nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

        // Anon request for the private version on the same name should still 401.
        var anonPrivateResp = await anonClient.GetAsync($"/nuget/flatcontainer/{id}/99.0.0/{id}.99.0.0.nupkg");
        Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
    }

    // ── PyPi: download routes by per-version origin ────────────────────────────

    [Fact]
    public async Task PyPi_Download_RoutesByVersionOrigin_PrivateRequiresAuth_ProxyDoesNot()
    {
        var name = $"pypiroute{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushPyPiPackage(name, "99.0.0");

        // Default test org has AnonymousPull=false. Turn it on for this test so anon access
        // to the proxy-cached version is allowed by tenant policy. The point being tested is
        // that uploaded versions still gate even when anon access is permitted; not the
        // tenant-wide anon toggle itself. The DependablyFactory is shared across tests in
        // this class (IClassFixture), so we restore the setting in a finally block below.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn0 = await store.OpenAsync();
        var orgId = await conn0.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn0.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId });
        try
        {

        // Prime a proxy-fetched version. The simplest path is to mock the simple index
        // and the file download so the proxy flow creates a package_versions row.
        var underscored = name.Replace('-', '_');
        var publicFilename = $"{underscored}-1.0.0-py3-none-any.whl";

        // The simple-index href must point at a URL the test environment can reach. Use the
        // MockUpstream's own base so DownloadAndCacheAsync's GET resolves to a mocked response.
        var mockBase = _factory.MockUpstream.Urls[0];
        var simpleHtml = $"""
            <!DOCTYPE html><html><body>
            <a href="{mockBase}/files/{publicFilename}#sha256=cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe">{publicFilename}</a><br/>
            </body></html>
            """;
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html").WithBody(simpleHtml));

        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/files/{publicFilename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        // Prime cache via authenticated request.
        var token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBasic(token);
        var primeResp = await authClient.GetAsync($"/packages/{publicFilename}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // Anon request for the proxy version → 200 (no auth required for proxy-cached).
        using var anonClient = _factory.CreateClient();
        var anonProxyResp = await anonClient.GetAsync($"/packages/{publicFilename}");
        Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

        // Anon request for the privately uploaded version → 401.
        var privateFilename = $"{underscored}-99.0.0-py3-none-any.whl";
        var anonPrivateResp = await anonClient.GetAsync($"/packages/{privateFilename}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
        }
        finally
        {
            await conn0.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
                new { orgId });
        }
    }

    // ── Npm: tarball routes by per-version origin ─────────────────────────────

    [Fact]
    public async Task Npm_Tarball_RoutesByVersionOrigin_PrivateRequiresAuth_ProxyDoesNot()
    {
        var name = $"npmroute{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNpmPackage(name, "99.0.0");

        // Mock the upstream packument so the proxy-fetch path can resolve version 1.0.0,
        // and the tarball blob itself.
        var publicTarball = $"{name}-1.0.0.tgz";
        var packumentJson = $$"""
        {
          "_id": "{{name}}",
          "name": "{{name}}",
          "dist-tags": {"latest":"1.0.0"},
          "versions": {
            "1.0.0": {
              "name": "{{name}}",
              "version": "1.0.0",
              "dist": {"tarball":"http://upstream/{{name}}/-/{{publicTarball}}","shasum":"deadbeef"}
            }
          }
        }
        """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packumentJson));

        var (tarballBytes, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{name}/-/{publicTarball}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarballBytes));

        // Prime cache for 1.0.0 (proxy origin).
        var token = await _factory.CreateToken("pull");
        using var authClient = _factory.CreateClientWithBearer(token);
        var primeResp = await authClient.GetAsync($"/npm/tarballs/{name}/{publicTarball}");
        Assert.Equal(HttpStatusCode.OK, primeResp.StatusCode);

        // Anon request for the proxy version → 200.
        using var anonClient = _factory.CreateClient();
        var anonProxyResp = await anonClient.GetAsync($"/npm/tarballs/{name}/{publicTarball}");
        Assert.Equal(HttpStatusCode.OK, anonProxyResp.StatusCode);

        // Anon request for the private version → 401.
        var privateTarball = $"{name}-99.0.0.tgz";
        var anonPrivateResp = await anonClient.GetAsync($"/npm/tarballs/{name}/{privateTarball}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonPrivateResp.StatusCode);
    }

    // ── Cross-cutting: ProxyPassthroughDisabled honors the gate ─────────────────

    [Fact]
    public async Task NuGet_Index_PassthroughDisabled_ReturnsLocalOnlyWithSkippedHeader()
    {
        var id = $"passthroughoff{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Turn off passthrough.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var orgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, proxy_passthrough_enabled, max_osv_score_tolerance)
            VALUES (@orgId, 0, 10.0)
            ON CONFLICT(org_id) DO UPDATE SET proxy_passthrough_enabled = 0
            """,
            new { orgId });

        try
        {
            var token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);
            var resp = await client.GetAsync($"/nuget/flatcontainer/{id}/index.json");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("skipped", resp.Headers.GetValues("X-Upstream-Status").FirstOrDefault());

            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var versions = doc.RootElement.GetProperty("versions").EnumerateArray()
                .Select(v => v.GetString()).ToList();
            Assert.Single(versions);
            Assert.Equal("1.0.0", versions[0]);
        }
        finally
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
                new { orgId });
        }
    }
}
