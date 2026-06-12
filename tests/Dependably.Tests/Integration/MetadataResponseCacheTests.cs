using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that npm packument, PyPI simple index, and NuGet registration responses
/// are served from the in-process IMemoryCache on repeat requests, and that the cache
/// entry is evicted whenever the package is mutated (publish, delete).
/// </summary>
[Trait("Category", "Integration")]
public sealed partial class MetadataResponseCacheTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    // PEP 503 name-normalization separators: a run of '-', '_', or '.' collapses to '-'.
    [GeneratedRegex(@"[-_\.]+")]
    private static partial Regex Pep503SeparatorRegex();

    private readonly DependablyFactory _factory;

    public MetadataResponseCacheTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── npm ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// A second GET of the same packument must be served from the in-process cache.
    /// The IMemoryCache entry is present under the key metadata:{orgId}:npm:{name} after
    /// the first request populates it.
    /// </summary>
    [Fact]
    public async Task Npm_SecondPackumentRequest_HitsCache()
    {
        const string pkg = "cache-hit-npm-pkg";
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // First request — populates the cache.
        var resp1 = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();

        // Resolve the orgId to construct the expected cache key.
        var cache = _factory.Services.GetRequiredService<IMemoryCache>();
        var orgs = _factory.Services.GetRequiredService<Dependably.Infrastructure.OrgRepository>();
        var org = await orgs.GetBySlugAsync("default");
        string cacheKey = $"metadata:{org!.Id}:npm:{pkg}";

        Assert.True(cache.TryGetValue<byte[]>(cacheKey, out byte[]? cached), "Cache entry must exist after first fetch.");
        Assert.NotNull(cached);

        // Second request — reads from cache.
        var resp2 = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();

        Assert.Equal(body1, body2);
    }

    /// <summary>
    /// Publishing a second version of the same package must evict the packument cache
    /// entry so that the subsequent GET reflects the new version.
    /// </summary>
    [Fact]
    public async Task Npm_Publish_InvalidatesPackumentCache()
    {
        const string pkg = "cache-evict-npm-pkg";
        await _factory.PushNpmPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        // Warm the cache.
        var resp1 = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();
        using var doc1 = JsonDocument.Parse(body1);
        Assert.True(doc1.RootElement.GetProperty("versions").TryGetProperty("1.0.0", out _),
            "v1.0.0 must be present before invalidation.");

        // Publish a second version — triggers cache eviction.
        await _factory.PushNpmPackage(pkg, "2.0.0");

        // After eviction, the packument must include both versions.
        var resp2 = await client.GetAsync($"/npm/{pkg}");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();
        using var doc2 = JsonDocument.Parse(body2);
        Assert.True(doc2.RootElement.GetProperty("versions").TryGetProperty("2.0.0", out _),
            "v2.0.0 must appear after cache is evicted by second publish.");
    }

    // ── PyPI ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// A second GET of the same PyPI simple index must be served from the in-process cache.
    /// The IMemoryCache entry is present under metadata:{orgId}:pypi:{normalized-name} after
    /// the first request populates it.
    /// </summary>
    [Fact]
    public async Task PyPi_SecondSimpleIndexRequest_HitsCache()
    {
        const string pkg = "cache-hit-pypi-pkg";
        await _factory.PushPyPiPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // First request — populates the cache.
        var resp1 = await client.GetAsync($"/simple/{pkg}/");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();

        // PyPI normalizes names: hyphens → hyphens (already canonical after PEP 503).
        var cache = _factory.Services.GetRequiredService<IMemoryCache>();
        var orgs = _factory.Services.GetRequiredService<Dependably.Infrastructure.OrgRepository>();
        var org = await orgs.GetBySlugAsync("default");
        // PEP 503 normalization: lower, replace [-_.] with '-'.
        string normalizedName = Pep503SeparatorRegex().Replace(pkg.ToLowerInvariant(), "-");
        string cacheKey = $"metadata:{org!.Id}:pypi:{normalizedName}";

        Assert.True(cache.TryGetValue<byte[]>(cacheKey, out byte[]? cached), "Cache entry must exist after first fetch.");
        Assert.NotNull(cached);

        // Second request — reads from cache.
        var resp2 = await client.GetAsync($"/simple/{pkg}/");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();

        Assert.Equal(body1, body2);
    }

    /// <summary>
    /// Publishing a new version of a PyPI package must evict the simple-index cache entry
    /// so that the subsequent GET reflects the new file.
    /// </summary>
    [Fact]
    public async Task PyPi_Publish_InvalidatesSimpleIndexCache()
    {
        const string pkg = "cache-evict-pypi-pkg";
        await _factory.PushPyPiPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Warm the cache.
        var resp1 = await client.GetAsync($"/simple/{pkg}/");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();
        Assert.Contains("1.0.0", body1, StringComparison.Ordinal);

        // Publish a second version — triggers cache eviction.
        await _factory.PushPyPiPackage(pkg, "2.0.0");

        // After eviction, the index must list both versions.
        var resp2 = await client.GetAsync($"/simple/{pkg}/");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();
        Assert.Contains("2.0.0", body2, StringComparison.Ordinal);
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// A second GET of the same NuGet registration index must be served from the
    /// in-process cache. The IMemoryCache entry is present under
    /// metadata:{orgId}:nuget:{id}:sv1 after the first request populates it.
    /// </summary>
    [Fact]
    public async Task NuGet_SecondRegistrationRequest_HitsCache()
    {
        // Use a unique lower-case name to avoid cross-test collisions; NuGet normalises
        // package ids to lower-case, so both the route and the cache key must be lower-case.
        string pkg = $"cache-hit-nuget-{Guid.NewGuid():N}"[..28];
        await _factory.PushNuGetPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // NuGet registration — semver1 variant (/nuget/registration/{id}/).
        string url = $"/nuget/registration/{pkg}/index.json";
        var resp1 = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();

        var cache = _factory.Services.GetRequiredService<IMemoryCache>();
        var orgs = _factory.Services.GetRequiredService<Dependably.Infrastructure.OrgRepository>();
        var org = await orgs.GetBySlugAsync("default");
        string sv1Key = $"metadata:{org!.Id}:nuget:{pkg}:sv1";

        Assert.True(cache.TryGetValue<byte[]>(sv1Key, out byte[]? cached), "Cache entry must exist after first fetch.");
        Assert.NotNull(cached);

        // Second request — reads from cache.
        var resp2 = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();

        Assert.Equal(body1, body2);
    }

    /// <summary>
    /// Pushing a new NuGet package version must evict both sv1 and sv2 registration cache
    /// entries so that the subsequent GET reflects the new version.
    /// </summary>
    [Fact]
    public async Task NuGet_Publish_InvalidatesRegistrationCache()
    {
        string pkg = $"cache-evict-nuget-{Guid.NewGuid():N}"[..30];
        await _factory.PushNuGetPackage(pkg, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string url = $"/nuget/registration/{pkg}/index.json";

        // Warm the cache.
        var resp1 = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        string body1 = await resp1.Content.ReadAsStringAsync();
        Assert.Contains("1.0.0", body1, StringComparison.Ordinal);

        // Publish a second version — triggers cache eviction.
        await _factory.PushNuGetPackage(pkg, "2.0.0");

        // After eviction, the registration must list both versions.
        var resp2 = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        string body2 = await resp2.Content.ReadAsStringAsync();
        Assert.Contains("2.0.0", body2, StringComparison.Ordinal);
    }
}
