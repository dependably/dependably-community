using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Headless-edge behaviour proven against the <see cref="EdgeFactory"/> — the second
/// WebApplicationFactory bound to the <c>Dependably.Edge</c> composition root's own <c>Program</c>.
/// Where <c>EdgeHeadlessTests</c> exercises the runtime <c>DEPLOYMENT_MODE=edge</c> path on the
/// full root (management controllers present but stripped by routing convention), these tests
/// exercise the structural guarantee: the Edge root has no management controllers to begin with,
/// so every management route is a plain route miss and there is no admin bootstrap path at all.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeRootHeadlessTests
{
    private const string EdgeToken = EdgeFactory.DefaultEdgeToken;

    // ── 1. Boot: healthy, org seeded, upstreams seeded, NO admin user ────────────

    [Fact]
    public async Task EdgeRoot_Boots_Healthy_SeedsOrgAndUpstreams_NoAdminUser()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();

        // The single implicit edge org is seeded.
        int orgs = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM orgs");
        Assert.Equal(1, orgs);

        // Master upstream rows seeded (one per ecosystem) pointing at the master.
        int upstreams = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM upstream_registry");
        Assert.True(upstreams > 0, "edge first-boot must seed master upstream rows");

        // No admin user — IAdminBootstrapper is never registered on the edge root, and the edge
        // first-boot branch creates no BCrypt admin account.
        int users = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM users");
        Assert.Equal(0, users);
    }

    // ── 2. Management routes 404 by absence (no controller exists) ────────────────

    public static TheoryData<string, string> ManagementRoutes() => new()
    {
        { "GET", "/api/v1/orgs" },
        { "POST", "/api/v1/auth/login" },
        { "GET", "/api/v1/system/tenants" },
        { "GET", "/saml/metadata" },
        { "POST", "/api/v1/bootstrap" },
        { "GET", "/api/v1/instance/settings" },
    };

    [Theory]
    [MemberData(nameof(ManagementRoutes))]
    public async Task EdgeRoot_ManagementRoutes_Return404_ByAbsence(string method, string path)
    {
        await using var f = new EdgeFactory { EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        var resp = await client.SendAsync(req);

        // 404 = no controller mapped this route (structural absence). A JWT-challenge shape
        // (401 + WWW-Authenticate) would mean an auth pipeline is guarding a real endpoint — the
        // edge root has neither the controller nor the JwtBearer challenge.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.False(resp.Headers.Contains("WWW-Authenticate"),
            "a route miss must not emit a JWT/auth challenge — that would imply the endpoint exists");
    }

    // ── 3. Protocol reads work against a stubbed master, Bearer header asserted ───

    [Fact]
    public async Task EdgeRoot_NpmTarball_Proxied_FromMaster_WithBearer()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        string name = $"edgeroot{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        var (tarball, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        string file = $"{name}-1.0.0.tgz";
        f.MockUpstream
            .Given(Request.Create().WithPath($"/npm/{name}/-/{file}")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        using var client = f.CreateClient();
        var resp = await client.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(tarball, await resp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task EdgeRoot_PyPiJson_Proxied_FromMaster_WithBearer()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        string name = $"edgepypi{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string jsonDoc = $$"""
            { "info": { "name": "{{name}}", "version": "1.0.0" },
              "releases": { "1.0.0": [] } }
            """;
        f.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/json")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(jsonDoc));

        using var client = f.CreateClient();
        var resp = await client.GetAsync($"/pypi/{name}/json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("1.0.0", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task EdgeRoot_NuGetServiceIndex_Served()
    {
        // The NuGet v3 service index is generated locally (no upstream fetch) — it proves the
        // NuGet protocol controller is mapped and serving on the edge root without a master stub.
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var client = f.CreateClient();

        var resp = await client.GetAsync("/nuget/v3/index.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        // The service index advertises the resource endpoints; "version" is always present.
        Assert.Contains("resources", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── 4. EDGE_ACCESS_TOKEN semantics (tokened vs anonymous) ────────────────────

    [Fact]
    public async Task EdgeRoot_WithAccessToken_AnonymousDenied_TokenedServed_RowSeeded()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = "inbound-secret" };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            int anon = await conn.ExecuteScalarAsync<int>("SELECT anonymous_pull FROM org_settings LIMIT 1");
            Assert.Equal(0, anon);
            int rows = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM service_tokens WHERE description = @d",
                new { d = EdgeAccessTokenSeeder.TokenDescription });
            Assert.Equal(1, rows);
        }

        string name = $"edgeauth{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        var (tarball, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        string file = $"{name}-1.0.0.tgz";
        f.MockUpstream
            .Given(Request.Create().WithPath($"/npm/{name}/-/{file}")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        // Anonymous inbound read denied (anonymous_pull off).
        using var anon2 = f.CreateClient();
        var anonResp = await anon2.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonResp.StatusCode);

        // Seeded inbound token authenticates and serves the proxied artifact.
        using var authed = f.CreateClientWithBearer("inbound-secret");
        var okResp = await authed.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, okResp.StatusCode);
        Assert.Equal(tarball, await okResp.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task EdgeRoot_NoAccessToken_AnonymousServed_NoTokenRow_WarningLogged()
    {
        var sink = new CapturingLogSink();
        await using var f = new EdgeFactory { EdgeAccessToken = null, LogSink = sink };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            int anon = await conn.ExecuteScalarAsync<int>("SELECT anonymous_pull FROM org_settings LIMIT 1");
            Assert.Equal(1, anon);
            int rows = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM service_tokens WHERE description = @d",
                new { d = EdgeAccessTokenSeeder.TokenDescription });
            Assert.Equal(0, rows);
        }

        // The anonymous-mode startup warning fired.
        Assert.True(sink.Contains("anonymous", Serilog.Events.LogEventLevel.Warning),
            "the edge root must log the anonymous-clients warning at startup when no access token is set");

        string name = $"edgeanon{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        var (tarball, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        string file = $"{name}-1.0.0.tgz";
        f.MockUpstream
            .Given(Request.Create().WithPath($"/npm/{name}/-/{file}")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        using var anonClient = f.CreateClient();
        var resp = await anonClient.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(tarball, await resp.Content.ReadAsByteArrayAsync());
    }

    // ── 5. Publish attempts → 405 via EdgePublishGuard ───────────────────────────

    [Fact]
    public async Task EdgeRoot_NpmPublish_FailsClosed_405()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        // A push-capable token so the request passes the per-endpoint capability gate and reaches
        // the EdgePublishGuard — proving the guard (not an auth failure) returns 405.
        string push = await f.CreateToken("push");
        using var client = f.CreateClientWithBearer(push);

        string body = NpmFixtures.BuildPublishBody("edgepub-npm", "1.0.0");
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/edgepub-npm", content);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
    }

    [Fact]
    public async Task EdgeRoot_OciPushInit_FailsClosed_405()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        string push = await f.CreateToken("push");
        using var client = f.CreateClientWithBearer(push);

        var resp = await client.PostAsync("/v2/edgepub-oci/blobs/uploads/", content: null);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, resp.StatusCode);
    }

    // ── 6. /edge/status + /health + /ready serve ─────────────────────────────────

    [Fact]
    public async Task EdgeRoot_StatusAndProbes_Serve()
    {
        await using var f = new EdgeFactory { EdgeAccessToken = null };
        using var client = f.CreateClient();

        var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        var ready = await client.GetAsync("/ready");
        Assert.True(ready.StatusCode is HttpStatusCode.OK or HttpStatusCode.ServiceUnavailable,
            "readiness returns 200 (ready) or 503 (degraded) — never a 404");

        var status = await client.GetAsync("/edge/status");
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        string statusBody = await status.Content.ReadAsStringAsync();
        Assert.Contains("\"deploymentMode\":\"edge\"", statusBody);
    }
}
