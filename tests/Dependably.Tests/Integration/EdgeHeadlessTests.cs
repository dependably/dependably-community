using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// Phase 2 headless gating for <c>DEPLOYMENT_MODE=edge</c>: the management plane 404s, protocol
/// reads still work, inbound client auth is governed by <c>EDGE_ACCESS_TOKEN</c> (tokened vs
/// anonymous), publish/push/import fail closed with a 405, and no session can be issued.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EdgeHeadlessTests
{
    private const string EdgeToken = DependablyFactory.DefaultEdgeToken;

    // Management routes that must 404 on an edge node (routing convention strips the controller).
    public static IEnumerable<object[]> ManagementRoutes()
    {
        yield return ["GET", "/api/v1/orgs"];
        yield return ["POST", "/api/v1/auth/login"];
        yield return ["GET", "/api/v1/system/tenants"];
        yield return ["GET", "/saml/metadata"];
        yield return ["POST", "/api/v1/bootstrap"];
        yield return ["GET", "/api/v1/instance/settings"];
    }

    [Theory]
    [MemberData(nameof(ManagementRoutes))]
    public async Task Edge_ManagementRoutes_Return404(string method, string path)
    {
        await using var f = new DependablyFactory { DeploymentMode = "edge", EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        using var req = new HttpRequestMessage(new HttpMethod(method), path);
        var resp = await client.SendAsync(req);

        // 404 = route not mapped (stripped). A 401/403/400 would mean the controller is still
        // reachable — the whole point of headless gating is that it is not.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Edge_LoginRoute_404_NoSessionCanBeIssued()
    {
        await using var f = new DependablyFactory { DeploymentMode = "edge", EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        var resp = await client.PostAsync("/api/v1/auth/login",
            new StringContent("""{"email":"a@b.c","password":"x"}""", System.Text.Encoding.UTF8, "application/json"));

        // With the auth controller stripped, no login endpoint exists → no JWT session issuable.
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task Edge_HealthAndProtocolPing_StillServed()
    {
        await using var f = new DependablyFactory { DeploymentMode = "edge", EdgeAccessToken = "inbound-tok" };
        using var client = f.CreateClient();

        // Health is a minimal-API endpoint, not a controller — never stripped.
        var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);

        // The OCI /v2/ ping is a protocol surface — kept and reachable (auth handled per-request).
        var ping = await client.GetAsync("/v2/");
        Assert.NotEqual(HttpStatusCode.NotFound, ping.StatusCode);
    }

    // ── Inbound auth: tokened mode ───────────────────────────────────────────────

    [Fact]
    public async Task Edge_WithAccessToken_AnonymousReadDenied_TokenedReadServed_RowSeeded()
    {
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            EdgeAccessToken = "inbound-secret",
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        // anonymous_pull off + a reader service-token row named for the access token.
        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            int anon = await conn.ExecuteScalarAsync<int>("SELECT anonymous_pull FROM org_settings LIMIT 1");
            Assert.Equal(0, anon);

            var (Caps, Desc) = await conn.QuerySingleOrDefaultAsync<(string? Caps, string? Desc)>(
                "SELECT capabilities AS Caps, description AS Desc FROM service_tokens WHERE description = @d",
                new { d = EdgeAccessTokenSeeder.TokenDescription });
            Assert.Equal(Dependably.Security.Capabilities.ReaderCapsCanonicalJson, Caps);
            Assert.Equal(EdgeAccessTokenSeeder.TokenDescription, Desc);
        }

        // Stub a master npm tarball fetch gated on the edge master Bearer token.
        string name = $"edgeauth{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        var (tarball, _, _) = NpmFixtures.BuildTarball(name, "1.0.0");
        string file = $"{name}-1.0.0.tgz";
        f.MockUpstream
            .Given(Request.Create().WithPath($"/npm/{name}/-/{file}")
                .WithHeader("Authorization", $"Bearer {EdgeToken}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream").WithBody(tarball));

        // Anonymous inbound read is denied (anonymous_pull is off).
        using var anonClient = f.CreateClient();
        var anonResp = await anonClient.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonResp.StatusCode);

        // Presenting the seeded inbound token authenticates and serves the (proxied) artifact.
        using var authed = f.CreateClientWithBearer("inbound-secret");
        var okResp = await authed.GetAsync($"/npm/tarballs/{name}/{file}");
        Assert.Equal(HttpStatusCode.OK, okResp.StatusCode);
        Assert.Equal(tarball, await okResp.Content.ReadAsByteArrayAsync());
    }

    // ── Inbound auth: anonymous mode ─────────────────────────────────────────────

    [Fact]
    public async Task Edge_NoAccessToken_AnonymousReadServed_NoTokenRow()
    {
        await using var f = new DependablyFactory
        {
            DeploymentMode = "edge",
            EdgeAccessToken = null,
        };
        using var boot = f.CreateClient();
        await boot.GetAsync("/health");

        var db = f.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await db.OpenAsync())
        {
            int anon = await conn.ExecuteScalarAsync<int>("SELECT anonymous_pull FROM org_settings LIMIT 1");
            Assert.Equal(1, anon);
            int tokenRows = await conn.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM service_tokens WHERE description = @d",
                new { d = EdgeAccessTokenSeeder.TokenDescription });
            Assert.Equal(0, tokenRows);
        }

        // Anonymous inbound read is served (proxied from the master).
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
}
