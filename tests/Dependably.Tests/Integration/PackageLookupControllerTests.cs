using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of <c>GET /api/v1/lookup</c>: auth (a ReadPackages-capable member can run
/// a lookup, anonymous is rejected), camelCase response shape, the 200 found/not-found verdict
/// split, RFC 7807 problem details for a malformed name or unknown ecosystem, and that the
/// endpoint is read-only (a lookup never creates a package/version row nor caches an artifact).
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


    private void StubCargoIndex(string name, params string[] versions)
    {
        string body = string.Join('\n', versions.Select(v =>
            $$"""{"name":"{{name}}","vers":"{{v}}","cksum":"aa","yanked":false}"""));
        _factory.MockUpstream.Given(
            Request.Create().WithPath($"/{CargoController.IndexPath(name)}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/plain").WithBody(body));
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

    // A lookup is a query about a candidate, so "upstream has no such package" is an answer to
    // it — served 200 with found=false, echoing the coordinate that was resolved. Mistyping a
    // name is the ordinary way to reach this and must not be reported as a failed request.
    [Fact]
    public async Task PackageNotFoundUpstream_Returns200WithFoundFalse()
    {
        string name = $"lookup-missing-{Guid.NewGuid():N}"[..24];
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.False(doc.RootElement.GetProperty("found").GetBoolean());
        Assert.Equal("npm", doc.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal(name, doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("1.0.0", doc.RootElement.GetProperty("version").GetString());
        // The not-found body carries no verdict — a client must not read one out of it.
        Assert.False(doc.RootElement.TryGetProperty("verdict", out _));
    }

    // The found shape carries the same discriminator set to true, so a client branches on
    // `found` rather than on the status code (both are 200).
    [Fact]
    public async Task PackageFoundUpstream_Returns200WithFoundTrue()
    {
        string name = $"lookup-present-{Guid.NewGuid():N}"[..24];
        StubNpmPackument(name, "1.0.0");
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=npm&name={name}&version=1.0.0");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.GetProperty("found").GetBoolean());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("verdict").GetString()));
    }

    // A bare "@scope" with no name part is a malformed npm name, not an absent package.
    // registry.npmjs.org answers it with 405 (not 404), so forwarding it upstream would report a
    // caller's typo as an unhealthy upstream (503). It is rejected as invalid input instead, and
    // no upstream request is made at all.
    [Fact]
    public async Task BareNpmScope_Returns422_AndNeverReachesUpstream()
    {
        using var client = await MemberClient();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=npm&name=%40dependably");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(422, doc.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain(
            _factory.MockUpstream.LogEntries,
            e => e.RequestMessage?.Path?.Contains("dependably", StringComparison.Ordinal) == true);
    }

    // End-to-end proof of the double-encoding traversal defence: the wire bytes are
    // "%252e%252e%252fadmin", which ASP.NET decodes ONCE to the literal string "%2e%2e%2fadmin"
    // — no literal ".." or "/", so it clears the base path-safety rules and would be decoded to
    // "../admin" by the upstream. The '%'-ban in ValidateUpstreamSegment rejects it as 422 and
    // no upstream request is composed. Single-encoding ("%2e%2e%2f") is already caught because
    // ASP.NET decodes it to a literal "../" that the base rules reject.
    [Fact]
    public async Task DoubleEncodedTraversalName_Returns422_AndNeverReachesUpstream()
    {
        using var client = await MemberClient();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=pypi&name=%252e%252e%252fadmin&version=1.0");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(422, doc.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain(
            _factory.MockUpstream.LogEntries,
            e => e.RequestMessage?.Path?.Contains("admin", StringComparison.Ordinal) == true);
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

    /// <summary>
    /// The reported bug at the HTTP boundary: a cargo lookup with no version used to answer 422
    /// "version is required for ecosystem 'cargo'". It now resolves the latest version from the
    /// sparse index and says which one it picked.
    /// </summary>
    [Fact]
    public async Task Lookup_Cargo_NoVersion_Returns200_NotVersionRequired422()
    {
        string name = $"lookupcrate{Guid.NewGuid():N}"[..20];
        StubCargoIndex(name, "0.9.0", "1.2.0");
        using var client = await MemberClient();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=cargo&name={name}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("found").GetBoolean());
        Assert.Equal("1.2.0", body.GetProperty("version").GetString());
        Assert.True(body.GetProperty("versionInferred").GetBoolean());
    }

    /// <summary>
    /// Go gained the same version-optional resolution as cargo, via the module proxy's @latest.
    /// </summary>
    [Fact]
    public async Task Lookup_Golang_NoVersion_Returns200_NotVersionRequired422()
    {
        string module = $"example.com/{Guid.NewGuid():N}"[..28];
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{module}/@latest").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody("""{"Version":"v1.5.0","Time":"2024-04-05T06:07:08Z"}"""));
        using var client = await MemberClient();

        var resp = await client.GetAsync(
            $"/api/v1/lookup?ecosystem=golang&name={Uri.EscapeDataString(module)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("v1.5.0", body.GetProperty("version").GetString());
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
