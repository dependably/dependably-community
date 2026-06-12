using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for ETag / If-None-Match / Cache-Control headers on metadata
/// and artifact endpoints. Verifies the ETag round-trip (GET → 304 on repeat) and
/// immutable Cache-Control on artifact downloads.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ETagCacheControlTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public ETagCacheControlTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── npm packument ────────────────────────────────────────────────────────

    [Fact]
    public async Task NpmPackument_Returns_ETag_And_304_On_ConditionalGet()
    {
        await _factory.PushNpmPackage("etag-npm-meta", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var first = await client.GetAsync("/npm/etag-npm-meta");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        string? etag = first.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.Matches("^\"[0-9a-f]{16}\"$", etag);

        // Strong ETag must not have W/ prefix.
        Assert.DoesNotContain("W/", etag);

        var req = new HttpRequestMessage(HttpMethod.Get, "/npm/etag-npm-meta");
        req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var conditional = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotModified, conditional.StatusCode);
        string body = await conditional.Content.ReadAsStringAsync();
        Assert.Empty(body);
    }

    [Fact]
    public async Task NpmPackument_LocalOnly_Has_LongMaxAge_CacheControl()
    {
        await _factory.PushNpmPackage("etag-npm-cc", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/etag-npm-cc");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("max-age=300", cc);
    }

    // ── npm tarball ──────────────────────────────────────────────────────────

    [Fact]
    public async Task NpmTarball_Returns_Immutable_CacheControl_And_ETag()
    {
        await _factory.PushNpmPackage("etag-npm-tarball", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        string json = await client.GetStringAsync("/npm/etag-npm-tarball");
        using var doc = JsonDocument.Parse(json);
        string tarballUrl = doc.RootElement
            .GetProperty("versions").GetProperty("1.0.0")
            .GetProperty("dist").GetProperty("tarball").GetString()!;

        var resp = await client.GetAsync(new Uri(tarballUrl).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? etag = resp.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.StartsWith("\"sha256:", etag);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("immutable", cc);
        Assert.Contains("max-age=31536000", cc);
    }

    // ── PyPI simple index ────────────────────────────────────────────────────

    [Fact]
    public async Task PyPiSimpleIndex_Returns_ETag_And_304_On_ConditionalGet()
    {
        await _factory.PushPyPiPackage("etag-pypi-meta", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var first = await client.GetAsync("/simple/etag-pypi-meta/");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        string? etag = first.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.Matches("^\"[0-9a-f]{16}\"$", etag);
        Assert.DoesNotContain("W/", etag);

        var req = new HttpRequestMessage(HttpMethod.Get, "/simple/etag-pypi-meta/");
        req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var conditional = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotModified, conditional.StatusCode);
        string body = await conditional.Content.ReadAsStringAsync();
        Assert.Empty(body);
    }

    [Fact]
    public async Task PyPiSimpleIndex_LocalOnly_Has_LongMaxAge_CacheControl()
    {
        await _factory.PushPyPiPackage("etag-pypi-cc", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/simple/etag-pypi-cc/");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("max-age=300", cc);
    }

    // ── PyPI artifact download ───────────────────────────────────────────────

    [Fact]
    public async Task PyPiArtifact_Returns_Immutable_CacheControl_And_ETag()
    {
        await _factory.PushPyPiPackage("etag-pypi-art", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Resolve the download URL from the simple index.
        string html = await client.GetStringAsync("/simple/etag-pypi-art/");
        int hrefStart = html.IndexOf("href=\"", StringComparison.Ordinal) + 6;
        int hrefEnd = html.IndexOf('"', hrefStart);
        string href = html[hrefStart..hrefEnd];

        // Strip any #sha256=… fragment before requesting.
        int fragmentIdx = href.IndexOf('#');
        string downloadPath = fragmentIdx >= 0 ? href[..fragmentIdx] : href;

        var resp = await client.GetAsync(downloadPath);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? etag = resp.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.StartsWith("\"sha256:", etag);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("immutable", cc);
        Assert.Contains("max-age=31536000", cc);
    }

    // ── NuGet registration ───────────────────────────────────────────────────

    [Fact]
    public async Task NuGetRegistration_Returns_ETag_And_304_On_ConditionalGet()
    {
        await _factory.PushNuGetPackage("ETagNugetMeta", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var first = await client.GetAsync("/nuget/registration/etagnugetmeta/index.json");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        string? etag = first.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.Matches("^\"[0-9a-f]{16}\"$", etag);
        Assert.DoesNotContain("W/", etag);

        var req = new HttpRequestMessage(HttpMethod.Get, "/nuget/registration/etagnugetmeta/index.json");
        req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var conditional = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotModified, conditional.StatusCode);
        string body = await conditional.Content.ReadAsStringAsync();
        Assert.Empty(body);
    }

    [Fact]
    public async Task NuGetRegistration_LocalOnly_Has_LongMaxAge_CacheControl()
    {
        await _factory.PushNuGetPackage("ETagNugetCC", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/nuget/registration/etagnugetcc/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("max-age=300", cc);
    }

    // ── NuGet artifact download ──────────────────────────────────────────────

    [Fact]
    public async Task NuGetArtifact_Returns_Immutable_CacheControl_And_ETag()
    {
        await _factory.PushNuGetPackage("ETagNugetArt", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/nuget/flatcontainer/etagnugetart/1.0.0/etagnugetart.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? etag = resp.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.StartsWith("\"sha256:", etag);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("immutable", cc);
        Assert.Contains("max-age=31536000", cc);
    }

    // ── Maven metadata ───────────────────────────────────────────────────────

    [Fact]
    public async Task MavenMetadata_Returns_ETag_And_304_On_ConditionalGet()
    {
        await _factory.PushMavenArtifact("com.example", "etag-maven-meta", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var first = await client.GetAsync("/maven/com/example/etag-maven-meta/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        string? etag = first.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.Matches("^\"[0-9a-f]{16}\"$", etag);
        Assert.DoesNotContain("W/", etag);

        var req = new HttpRequestMessage(HttpMethod.Get, "/maven/com/example/etag-maven-meta/maven-metadata.xml");
        req.Headers.TryAddWithoutValidation("If-None-Match", etag);
        var conditional = await client.SendAsync(req);

        Assert.Equal(HttpStatusCode.NotModified, conditional.StatusCode);
        string body = await conditional.Content.ReadAsStringAsync();
        Assert.Empty(body);
    }

    // ── Maven artifact ───────────────────────────────────────────────────────

    [Fact]
    public async Task MavenArtifact_Returns_Immutable_CacheControl_And_ETag()
    {
        await _factory.PushMavenArtifact("com.example", "etag-maven-art", "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync("/maven/com/example/etag-maven-art/1.0.0/etag-maven-art-1.0.0.jar");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? etag = resp.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.StartsWith("\"sha256:", etag);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("immutable", cc);
        Assert.Contains("max-age=31536000", cc);
    }

    // ── RPM package ──────────────────────────────────────────────────────────

    [Fact]
    public async Task RpmPackage_Returns_Immutable_CacheControl_And_ETag()
    {
        string file = await _factory.PushRpmPackage();
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/rpm/packages/{file}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string? etag = resp.Headers.ETag?.Tag;
        Assert.NotNull(etag);
        Assert.StartsWith("\"sha256:", etag);

        string? cc = resp.Headers.CacheControl?.ToString();
        Assert.NotNull(cc);
        Assert.Contains("immutable", cc);
        Assert.Contains("max-age=31536000", cc);
    }
}
