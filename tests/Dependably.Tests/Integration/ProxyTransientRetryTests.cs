using System.Net;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end tests pinning the transient upstream retry contract: a transient CDN
/// error (403/429/5xx) on a proxy cache-miss path must never reach the client as a
/// fatal 403 or 404. Instead:
/// <list type="bullet">
///   <item>If a retry within the same request succeeds, the client sees 200.</item>
///   <item>If retries are exhausted, the client sees 503 (with Retry-After) or 502 —
///         never 403, never 404.</item>
///   <item>A genuine upstream 404 still reaches the client as 404 (absence, not transience).</item>
/// </list>
/// Covers PyPI and npm (each has its own MISS-handler catch ladder). Pairs with the
/// unit-level retry tests in UpstreamClientTests.cs.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyTransientRetryTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ProxyTransientRetryTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── PyPI ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_PersistentUpstream403_ClientSees503_NotFatalForbidden()
    {
        // All upstream attempts return 403. The client must receive 503 (retryable),
        // not 403 (which package managers treat as fatal policy) and not 404 (absence).
        string name = $"pypifbd{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (_, sha256) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}#sha256={sha256}\">{filename}</a></body></html>"));

        // All artifact fetches return 403 — retries exhausted.
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.Forbidden));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");

        // Must not be 403 (fatal policy block that aborts installs).
        // Must not be 404 (absence — wrong signal for a transient outage).
        // Must be 503 (retryable — client can retry later).
        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.NotEqual(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    [Fact]
    public async Task PyPi_PersistentUpstream429_ClientSees503_WithRetryAfterHeader()
    {
        // 429 Too Many Requests with Retry-After must surface as 503 carrying the
        // Retry-After signal so clients back off correctly.
        string name = $"pypithrl{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (_, sha256) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}#sha256={sha256}\">{filename}</a></body></html>"));

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.TooManyRequests)
                .WithHeader("Retry-After", "15"));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        // Retry-After must be present and numeric.
        string? retryAfter = resp.Headers.TryGetValues("Retry-After", out var vals)
            ? vals.FirstOrDefault() : null;
        Assert.NotNull(retryAfter);
        Assert.True(int.TryParse(retryAfter, out int secs) && secs > 0);
    }

    [Fact]
    public async Task PyPi_Genuine404_ClientSees404_Unchanged()
    {
        // A genuine 404 (artifact doesn't exist upstream) must still reach the client
        // as 404 — the retry logic must not promote absence into 503.
        string name = $"pypi404{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string underscored = name.Replace('-', '_');
        string filename = $"{underscored}-{version}-py3-none-any.whl";
        var (_, sha256) = PyPiFixtures.BuildWheel(name, version);
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"<html><body><a href=\"{mockBase}/files/{filename}#sha256={sha256}\">{filename}</a></body></html>"));

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);
        var resp = await client.GetAsync($"/packages/{filename}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── npm ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_PersistentUpstream403_ClientSees503_NotFatalForbidden()
    {
        // npm tarballs go through FetchAndCacheByUrlAsync; the same retry contract applies.
        string name = $"npmfbd{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string filename = $"{name}-{version}.tgz";

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "dist": {}
                }
              }
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));

        // All tarball fetches return 403 — retries exhausted.
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.Forbidden));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");

        Assert.NotEqual(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.NotEqual(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    [Fact]
    public async Task Npm_Genuine404_ClientSees404_Unchanged()
    {
        // Genuine absent tarball stays 404 — absence must not be promoted to 503.
        string name = $"npm404{Guid.NewGuid():N}"[..18].ToLowerInvariant();
        string version = "1.0.0";
        string filename = $"{name}-{version}.tgz";

        string packument = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}", "version": "{{version}}",
                  "dist": {}
                }
              }
            }
            """;
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(packument));

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/{name}/-/{filename}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{filename}");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
