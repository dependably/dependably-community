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
/// Integration tests for NuGetController covering paths not exercised by
/// NuGetComplianceTests: anonymous-pull gate on Search, query-filter, upstream-404 on
/// FlatcontainerVersions, hosted-package auth gate on Flatcontainer, bad push payloads,
/// cross-tenant Unlist rejection, and GetSymbols 404.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NuGetControllerTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── Search: anonymous-pull disabled → 401 without token ──────────────────

    [Fact]
    public async Task Search_WithoutToken_Returns401()
    {
        // Default org has AnonymousPull=false (the zero-value default).
        // A request without any auth header must be rejected.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/nuget/query?q=anything");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Search: q= filter returns only matching packages ─────────────────────

    [Fact]
    public async Task Search_WithQueryFilter_ReturnsFilteredResults()
    {
        // Push two packages with distinct names so we can filter them.
        await _factory.PushNuGetPackage($"FilterMatchPkg{Guid.NewGuid():N}"[..20], "1.0.0");
        string matchId = $"SearchTarget{Guid.NewGuid():N}"[..20];
        await _factory.PushNuGetPackage(matchId, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Use a prefix that exists only in the target package name.
        var resp = await client.GetAsync($"/nuget/query?q=SearchTarget");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        int totalHits = doc.RootElement.GetProperty("totalHits").GetInt32();
        Assert.True(totalHits >= 1, "Expected at least one hit for the matching package.");

        // Every returned package must contain the search term in its id.
        foreach (var item in doc.RootElement.GetProperty("data").EnumerateArray())
        {
            string id = item.GetProperty("id").GetString()!;
            Assert.Contains("SearchTarget", id, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Search_OversizedTakeAndNegativeSkip_AreClampedNot500()
    {
        await _factory.PushNuGetPackage($"ClampPkg{Guid.NewGuid():N}"[..18], "1.0.0");
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Oversized take is clamped, not errored.
        var big = await client.GetAsync("/nuget/query?take=100000");
        Assert.Equal(HttpStatusCode.OK, big.StatusCode);

        // Negative skip previously threw in Enumerable.Skip → 500; now clamped to 0.
        var neg = await client.GetAsync("/nuget/query?skip=-1");
        Assert.Equal(HttpStatusCode.OK, neg.StatusCode);
    }

    // ── FlatcontainerVersions: no local versions + upstream 404 → 404 ────────

    [Fact]
    public async Task FlatcontainerVersions_NoLocalVersions_UpstreamReturns404_Returns404()
    {
        // Stub the upstream so requests for this package's version list return 404.
        string unknownId = $"NoLocalNoUpstreamPkg{Guid.NewGuid():N}"[..28].ToLowerInvariant();
        _factory.MockUpstream.Given(
                Request.Create()
                    .WithPath($"/flatcontainer/{unknownId}/index.json")
                    .UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/flatcontainer/{unknownId}/index.json");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Flatcontainer: hosted package without token → 401 ────────────────────

    [Fact]
    public async Task Flatcontainer_HostedPackage_WithoutToken_Returns401()
    {
        // Push a non-proxy (hosted) package so IsProxy=false in the DB.
        string id = $"HostedAuthPkg{Guid.NewGuid():N}"[..20];
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Request the .nupkg without any auth. ServeHostedNupkgAsync returns 401
        // when token is null, regardless of AnonymousPull.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync(
            $"/nuget/flatcontainer/{id.ToLowerInvariant()}/1.0.0/{id.ToLowerInvariant()}.1.0.0.nupkg");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── Push: non-multipart body → 400 ───────────────────────────────────────

    [Fact]
    public async Task Push_NoFormData_Returns400()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Send JSON instead of multipart/form-data — ReadPushBodyAsync returns 400.
        using var content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ── Push: multipart with no file attached → 422 ───────────────────────────

    [Fact]
    public async Task Push_EmptyMultipart_Returns422()
    {
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Multipart form but zero file parts — ReadPushBodyAsync returns 422.
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent("placeholder"), "notafile");
        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    // ── Unlist: token from a different org → 401 ─────────────────────────────

    [Fact]
    public async Task Unlist_TokenOrgMismatch_Returns401()
    {
        // Push a package to the default org.
        string id = $"UnlistMismatch{Guid.NewGuid():N}"[..22];
        await _factory.PushNuGetPackage(id, "1.0.0");

        // Create a second real org so the FK on service_tokens.org_id is satisfied.
        // A token whose org_id points to a different tenant than the request org
        // causes ResolveNuGetPushTokenAsync to return 401 (token.OrgId != orgId).
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var secondOrg = await orgRepo.CreateOrgAsync($"other-{Guid.NewGuid():N}"[..16]);

        string rawToken = Dependably.Security.TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(rawToken);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities)
            VALUES (@id, @orgId, @name, @hash, @caps)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = secondOrg.Id,
                name = $"mismatch-{Guid.NewGuid():N}",
                hash,
                caps = """["publish:*","read:artifact","read:metadata","yank:*"]"""
            });

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", rawToken);

        var resp = await client.DeleteAsync($"/nuget/publish/{id.ToLowerInvariant()}/1.0.0");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    // ── GetSymbols: package not in DB → 404 ──────────────────────────────────

    [Fact]
    public async Task GetSymbols_PackageNotFound_Returns404()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync(
            "/nuget/symbols/ghost-package/1.0.0/ghost-package.1.0.0.snupkg");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
