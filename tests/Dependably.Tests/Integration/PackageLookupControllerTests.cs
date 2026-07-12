using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of <c>GET /api/v1/lookup</c>: auth (a ReadPackages-capable member can run
/// a lookup, anonymous is rejected), camelCase response shape, RFC 7807 problem details for
/// unknown ecosystem / package-not-found upstream, and that the endpoint is read-only (a lookup
/// never creates a package/version row nor caches an artifact).
/// </summary>
[Trait("Category", "Integration")]
public sealed class PackageLookupControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public PackageLookupControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"lookup-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    private void StubNpmPackument(string name, string version, string license = "MIT")
    {
        string json = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "{{version}}" },
              "versions": {
                "{{version}}": { "name": "{{name}}", "version": "{{version}}", "license": "{{license}}" }
              },
              "time": { "{{version}}": "2024-03-01T00:00:00.000Z" }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(json));
    }

    [Fact]
    public async Task Member_CanLookupPackage_ReturnsCamelCaseVerdict()
    {
        string name = $"lookup-clean-{Guid.NewGuid():N}"[..24];
        StubNpmPackument(name, "1.0.0");
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        // camelCase per JsonSerializerDefaults.Web — PascalCase would be a frontend-facing bug.
        Assert.Equal("allowed", root.GetProperty("verdict").GetString());
        Assert.Equal("npm", root.GetProperty("ecosystem").GetString());
        Assert.Equal("1.0.0", root.GetProperty("version").GetString());
        Assert.False(root.GetProperty("versionInferred").GetBoolean());
        Assert.True(root.TryGetProperty("malware", out var malware));
        Assert.False(malware.GetProperty("detected").GetBoolean());
        Assert.True(root.TryGetProperty("vulnerabilities", out var vulns));
        Assert.True(vulns.GetProperty("available").GetBoolean());
        Assert.True(root.TryGetProperty("license", out _));
        Assert.True(root.TryGetProperty("unavailableChecks", out _));
    }

    [Fact]
    public async Task Member_NoVersionGiven_ResolvesLatestAndSaysWhichVersion()
    {
        string name = $"lookup-latest-{Guid.NewGuid():N}"[..24];
        StubNpmPackument(name, "3.1.4");
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("3.1.4", doc.RootElement.GetProperty("version").GetString());
        Assert.True(doc.RootElement.GetProperty("versionInferred").GetBoolean());
    }

    [Fact]
    public async Task Anonymous_IsRejected()
    {
        using var client = _factory.CreateClient();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=npm&name=whatever&version=1.0.0");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task UnknownEcosystem_ReturnsLocalized422ProblemDetail()
    {
        using var client = await MemberClient();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=deb&name=whatever&version=1.0.0");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(422, doc.RootElement.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("detail").GetString()));
    }

    [Fact]
    public async Task PackageNotFoundUpstream_Returns404ProblemDetail()
    {
        string name = $"lookup-missing-{Guid.NewGuid():N}"[..24];
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(404, doc.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task MissingVersion_UnreachableUpstream_Returns503_NeverFalseAllowed()
    {
        string name = $"lookup-unreachable-{Guid.NewGuid():N}"[..24];
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.ServiceUnavailable));
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    [Fact]
    public async Task Lookup_NeverCreatesPackageOrVersionRow()
    {
        string name = $"lookup-noingest-{Guid.NewGuid():N}"[..24];
        StubNpmPackument(name, "1.0.0");
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        // The lookup must not have created a package row — a subsequent packument GET for the
        // same never-published name is a plain proxy miss (the upstream stub still answers, but
        // there is no local package/version row backing it).
        var db = _factory.Services.GetRequiredService<Dependably.Infrastructure.IMetadataStore>();
        await using var conn = await db.OpenAsync();
        long packageCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(
            conn, "SELECT COUNT(*) FROM packages WHERE purl_name = @name AND ecosystem = 'npm'", new { name });
        Assert.Equal(0, packageCount);

        // Widened per the class doc's "nothing is written" guarantee: no proxy cache row, no
        // persisted vulnerability record, no upstream negative-cache entry, and no blob — a
        // future regression that starts writing any of these on the read-only lookup path
        // must be caught here, not discovered as a supply-chain-relevant side effect later.
        long cacheArtifactCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(
            conn, "SELECT COUNT(*) FROM cache_artifact WHERE name = @name AND ecosystem = 'npm'", new { name });
        Assert.Equal(0, cacheArtifactCount);

        long vulnerabilityCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(
            conn, "SELECT COUNT(*) FROM vulnerabilities WHERE package_name = @name AND ecosystem = 'npm'", new { name });
        Assert.Equal(0, vulnerabilityCount);

        long negativeCacheCount = await Dapper.SqlMapper.ExecuteScalarAsync<long>(
            conn, "SELECT COUNT(*) FROM upstream_negative_cache WHERE ecosystem = 'npm'");
        Assert.Equal(0, negativeCacheCount);

        Assert.Empty(_factory.BlobStore.GetKeys());
    }
}
