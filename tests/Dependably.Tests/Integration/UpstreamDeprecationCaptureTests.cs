using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage for the upstream-deprecation passthrough on the proxy first-fetch
/// path: npm <c>versions[v].deprecated</c>, PyPI <c>yanked</c> + <c>yanked_reason</c>, and
/// NuGet registration leaf <c>listed: false</c>. Each ecosystem covers happy path + not-flagged
/// + the mixed-failure / fallback shape so the bucket lights up under partial-failure scenarios.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UpstreamDeprecationCaptureTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public UpstreamDeprecationCaptureTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string?> QueryDeprecatedAsync(string ecosystem, string purlName, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.deprecated
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = @ecosystem AND p.purl_name = @purlName AND pv.version = @version
            ORDER BY pv.created_at DESC LIMIT 1
            """,
            new { ecosystem, purlName, version });
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_ProxyFirstFetch_CapturesDeprecatedFromPackument()
    {
        var name = $"npmdep{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        var filename = $"{name}-{version}.tgz";

        var packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "deprecated": "use foo@2 instead"
                }
              },
              "time": { "{{version}}": "2024-01-01T00:00:00Z" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("npm", name, version);
        Assert.Equal("use foo@2 instead", stored);
    }

    [Fact]
    public async Task Npm_ProxyFirstFetch_NotDeprecated_DeprecatedColumnNull()
    {
        var name = $"npmlive{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        var filename = $"{name}-{version}.tgz";

        var packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": { "name":"{{name}}","version":"{{version}}" }
              },
              "time": { "{{version}}": "2024-01-01T00:00:00Z" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("npm", name, version);
        Assert.Null(stored);
    }

    [Fact]
    public async Task Npm_ProxyFirstFetch_DeprecatedEmptyString_DeprecatedColumnNull()
    {
        var name = $"npmempty{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        var filename = $"{name}-{version}.tgz";

        var packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": { "name":"{{name}}","version":"{{version}}","deprecated":"" }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("npm", name, version);
        Assert.Null(stored);
    }

    // ── PyPI ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_ProxyFirstFetch_CapturesYankedReasonFromJsonApi()
    {
        var name = $"pypiyank{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        var mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        var jsonApi = $$"""
            {
              "info": { "name": "{{name}}", "version": "{{version}}" },
              "urls": [
                { "filename": "{{filename}}", "yanked": true, "yanked_reason": "CVE-2024-9999 critical" }
              ]
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonApi));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("pypi", name, version);
        Assert.Equal("CVE-2024-9999 critical", stored);
    }

    [Fact]
    public async Task PyPi_ProxyFirstFetch_YankedWithEmptyReason_FallsBackToLiteralYanked()
    {
        var name = $"pypiempty{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        var mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        var jsonApi = $$"""
            {
              "info": { "name": "{{name}}", "version": "{{version}}" },
              "urls": [
                { "filename": "{{filename}}", "yanked": true, "yanked_reason": null }
              ]
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonApi));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("pypi", name, version);
        Assert.Equal("Yanked", stored);
    }

    [Fact]
    public async Task PyPi_ProxyFirstFetch_NotYanked_DeprecatedColumnNull()
    {
        var name = $"pypilive{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        var version = "1.0.0";
        var underscored = name.Replace('-', '_');
        var filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        var mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        var jsonApi = $$"""
            {
              "info": { "name": "{{name}}", "version": "{{version}}" },
              "urls": [
                { "filename": "{{filename}}", "yanked": false }
              ]
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonApi));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("pypi", name, version);
        Assert.Null(stored);
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_ProxyFirstFetch_UnlistedUpstream_CapturesUnlistedSentinel()
    {
        var id = $"NuGetUnl{Guid.NewGuid():N}"[..18];
        var version = "1.2.3";
        var lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        var filename = $"{lowerId}.{version}.nupkg";

        var leaf = """{ "published": "2024-01-01T00:00:00+00:00", "listed": false }""";
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("nuget", lowerId, version);
        Assert.Equal("Unlisted upstream", stored);
    }

    [Fact]
    public async Task NuGet_ProxyFirstFetch_Listed_DeprecatedColumnNull()
    {
        var id = $"NuGetLst{Guid.NewGuid():N}"[..18];
        var version = "1.2.3";
        var lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        var filename = $"{lowerId}.{version}.nupkg";

        var leaf = """{ "published": "2024-01-01T00:00:00+00:00", "listed": true }""";
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("nuget", lowerId, version);
        Assert.Null(stored);
    }

    [Fact]
    public async Task NuGet_ProxyFirstFetch_RegistrationLeaf500_DeprecatedColumnNull()
    {
        // Partial-failure parallel: when the registration leaf is unreachable we still
        // serve the artefact, but the deprecation column stays NULL (we don't have a
        // signal). Mirrors the published-at fail-soft contract.
        var id = $"NuGetReg{Guid.NewGuid():N}"[..18];
        var version = "1.2.4";
        var lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        var filename = $"{lowerId}.{version}.nupkg";

        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        var token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var stored = await QueryDeprecatedAsync("nuget", lowerId, version);
        Assert.Null(stored);
    }
}
