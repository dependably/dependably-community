using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies the upstream first-publish timestamp (<c>package_versions.published_at</c>) is
/// captured on the proxy first-fetch path across the three ecosystems, and that the capture
/// is fail-soft — when the metadata API returns 5xx the artefact fetch still succeeds and
/// the column stays NULL rather than failing the request. Covers the success + partial-failure
/// pair per the test-partial-failure-scenarios rule.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PublishedAtCaptureTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public PublishedAtCaptureTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string?> QueryPublishedAtAsync(string ecosystem, string version)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.published_at
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.ecosystem = @ecosystem AND pv.version = @version
            ORDER BY pv.created_at DESC LIMIT 1
            """,
            new { ecosystem, version });
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_ProxyFirstFetch_CapturesPublishedAtFromPackumentTime()
    {
        string name = $"npmpub{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";
        const string upstreamIso = "2024-03-15T12:34:56.000Z";

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": { "{{version}}": { "name": "{{name}}", "version": "{{version}}" } },
              "time": { "{{version}}": "{{upstreamIso}}" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("npm", version);
        Assert.NotNull(stored);
        Assert.Equal(DateTimeOffset.Parse(upstreamIso).ToUniversalTime(),
            DateTimeOffset.Parse(stored!).ToUniversalTime());
    }

    [Fact]
    public async Task Npm_ProxyFirstFetch_PackumentReturns500_StillSucceeds_NullPublishedAt()
    {
        string name = $"npmfail{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "2.0.0";
        var (bytes, _, _) = NpmFixtures.BuildTarball(name, version);
        string filename = $"{name}-{version}.tgz";

        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("npm", version);
        Assert.Null(stored);
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_ProxyFirstFetch_CapturesPublishedAtFromRegistrationLeaf()
    {
        string id = $"NuGetPub{Guid.NewGuid():N}"[..18];
        string version = "1.2.3";
        string lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{lowerId}.{version}.nupkg";
        const string upstreamIso = "2023-09-30T14:23:31+00:00";

        string leaf = $$"""
            { "published": "{{upstreamIso}}", "listed": true }
            """;
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("nuget", version);
        Assert.NotNull(stored);
        Assert.Equal(DateTimeOffset.Parse(upstreamIso).ToUniversalTime(),
            DateTimeOffset.Parse(stored!).ToUniversalTime());
    }

    [Fact]
    public async Task NuGet_ProxyFirstFetch_RegistrationUnlistedSentinel_PublishedAtNull()
    {
        string id = $"NuGetUnl{Guid.NewGuid():N}"[..18];
        string version = "1.2.4";
        string lowerId = id.ToLowerInvariant();
        var (bytes, _) = NuGetFixtures.BuildNupkg(id, version);
        string filename = $"{lowerId}.{version}.nupkg";

        // NuGet's unlisted sentinel — TryFetchNuGetPublishedAt must coerce to null.
        string leaf = """{ "published": "1900-01-01T00:00:00+00:00", "listed": false }""";
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/registration5-semver1/{lowerId}/{version}.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(leaf));
        _factory.MockUpstream.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{version}/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(bytes));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{lowerId}/{version}/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("nuget", version);
        Assert.Null(stored);
    }

    // ── PyPI ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_ProxyFirstFetch_CapturesUploadTimeFromJsonApi()
    {
        string name = $"pypipub{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];
        const string uploadIso = "2024-06-21T18:45:00.123456Z";

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));

        string jsonApi = $$"""
            {
              "info": { "name": "{{name}}", "version": "{{version}}" },
              "urls": [
                { "filename": "{{filename}}", "upload_time_iso_8601": "{{uploadIso}}" }
              ]
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonApi));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("pypi", version);
        Assert.NotNull(stored);
        Assert.Equal(DateTimeOffset.Parse(uploadIso).ToUniversalTime(),
            DateTimeOffset.Parse(stored!).ToUniversalTime());
    }

    [Fact]
    public async Task PyPi_ProxyFirstFetch_JsonApiReturns500_StillSucceeds_NullPublishedAt()
    {
        string name = $"pypifail{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.1";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (wheelBytes, _) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}\">{filename}</a></body></html>"));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(wheelBytes));
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? stored = await QueryPublishedAtAsync("pypi", version);
        Assert.Null(stored);
    }
}
