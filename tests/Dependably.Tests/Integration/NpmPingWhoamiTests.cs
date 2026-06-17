using System.Net;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Coverage for the two npm CLI standard probes added in this change:
/// <c>GET /npm/-/ping</c> (no auth, returns <c>{}</c>) and <c>GET /npm/-/whoami</c>
/// (bearer-only, returns <c>{"username":"..."}</c>).
///
/// Both endpoints share the existing tenant context plumbing — the test factory uses
/// <c>SingleTenantResolver</c>, so the default tenant is implicit on every request.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmPingWhoamiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public NpmPingWhoamiTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    // ── /-/ping ─────────────────────────────────────────────────────────────

    /// <summary>
    /// <c>npm ping</c> hits this with no Authorization header — it must return 200 with an
    /// empty JSON object, matching registry.npmjs.org's response shape so the npm CLI prints
    /// "Ping success" rather than complaining about an unexpected body.
    /// </summary>
    [Fact]
    public async Task Ping_NoAuth_Returns200WithEmptyJsonObject()
    {
        using var client = _factory.CreateClient();

        var resp = await client.GetAsync("/npm/-/ping");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        Assert.Empty(doc.RootElement.EnumerateObject());
    }

    /// <summary>
    /// Ping responds the same way whether the caller is authenticated or not. Sanity-check
    /// that adding a Bearer header doesn't change the response — npm ping is intentionally
    /// auth-agnostic so it stays usable as a connectivity probe before tokens are configured.
    /// </summary>
    [Fact]
    public async Task Ping_WithBearer_StillReturns200()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync("/npm/-/ping");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("{}", (await resp.Content.ReadAsStringAsync()).Replace(" ", ""));
    }

    // ── /-/whoami ────────────────────────────────────────────────────────────

    /// <summary>
    /// User token resolves to the owner's <c>users.email</c>. The bootstrap admin is the
    /// canonical user-token holder in tests; we issue a token tied to that account and
    /// assert <c>{"username":"&lt;admin email&gt;"}</c>.
    /// </summary>
    [Fact]
    public async Task WhoAmI_UserToken_ReturnsOwnerEmail()
    {
        string raw = await _factory.CreateAdminToken();
        string expectedEmail = await GetBootstrapOwnerEmailAsync();

        using var client = _factory.CreateClientWithBearer(raw);
        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(expectedEmail, doc.RootElement.GetProperty("username").GetString());
    }

    /// <summary>
    /// Service tokens have no <c>UserId</c>; whoami projects the service-token name as
    /// <c>service:&lt;name&gt;</c> so CI consumers see a stable identifier rather than a 401.
    /// </summary>
    [Fact]
    public async Task WhoAmI_ServiceToken_ReturnsServicePrefixedName()
    {
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        string orgId = await DefaultOrgIdAsync();
        string name = $"ci-whoami-{Guid.NewGuid():N}";

        var (raw, _) = await tokens.CreateServiceTokenAsync(
            orgId, name,
            """["read:artifact","read:metadata"]""",
            expiresAt: null);

        using var client = _factory.CreateClientWithBearer(raw);
        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        Assert.Equal($"service:{name}", doc.RootElement.GetProperty("username").GetString());
    }

    /// <summary>
    /// No Authorization header → 401 with a <c>WWW-Authenticate: Bearer</c> challenge so
    /// npm prompts the user to run <c>npm login</c> rather than failing silently.
    /// </summary>
    [Fact]
    public async Task WhoAmI_NoAuth_Returns401WithWwwAuthenticate()
    {
        using var client = _factory.CreateClient();

        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// A syntactically-valid but unknown Bearer token must also produce 401 with the same
    /// challenge — npm should treat invalid creds and missing creds the same way at the
    /// whoami endpoint.
    /// </summary>
    [Fact]
    public async Task WhoAmI_InvalidBearer_Returns401WithWwwAuthenticate()
    {
        using var client = _factory.CreateClientWithBearer("not-a-real-token-" + Guid.NewGuid().ToString("N"));

        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Cross-tenant guard: a Bearer token issued for one org must NOT identify itself
    /// against another org's whoami endpoint. The org-scoped <c>ResolveTokenAsync</c>
    /// coerces the cross-tenant token to null, so the response is 401 — identical to
    /// the no-auth and invalid-token cases (no information leak about whether the token
    /// exists somewhere else).
    /// </summary>
    [Fact]
    public async Task WhoAmI_TokenForDifferentOrg_Returns401()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();

        await using var conn = await store.OpenAsync();
        string otherOrgId = Guid.NewGuid().ToString("N");
        string otherOrgSlug = $"other-whoami-{otherOrgId[..8]}";
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = otherOrgId, slug = otherOrgSlug });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id) VALUES (@orgId)",
            new { orgId = otherOrgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(otherOrgId);

        var (rawOtherToken, _) = await tokens.CreateServiceTokenAsync(
            otherOrgId,
            $"cross-org-whoami-{otherOrgId[..8]}",
            """["read:artifact","read:metadata"]""",
            expiresAt: null);

        // Test factory uses SingleTenantResolver — every request resolves to the default
        // org regardless of host. Presenting the other-org token there forces the
        // ResolveTokenAsync(expectedOrgId) cross-tenant null branch.
        using var client = _factory.CreateClientWithBearer(rawOtherToken);
        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    /// <summary>
    /// Expired user token: <see cref="TokenRepository.ResolveAsync"/> filters on
    /// <c>expires_at &gt; now</c>, so a token that resolves to null on the auth side
    /// hits the same 401 branch as a malformed Bearer.
    /// </summary>
    [Fact]
    public async Task WhoAmI_ExpiredToken_Returns401()
    {
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        string orgId = await DefaultOrgIdAsync();

        var (raw, record) = await tokens.CreateServiceTokenAsync(
            orgId, $"expired-{Guid.NewGuid():N}",
            """["read:artifact","read:metadata"]""",
            // now-ok: token must be valid at creation relative to the host's real clock; backdated below.
            expiresAt: DateTimeOffset.UtcNow.AddHours(1));

        // Backdate expires_at to the past so the resolver's WHERE clause filters it out.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE service_tokens SET expires_at = @past WHERE id = @id",
                // now-ok: seeds relative to the host's real clock so the resolver's
                // expires_at > now filter rejects it; 1h clears the cutoff by a wide margin.
                new { past = DateTimeOffset.UtcNow.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"), id = record.Id });
        }

        using var client = _factory.CreateClientWithBearer(raw);
        var resp = await client.GetAsync("/npm/-/whoami");

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private async Task<string> DefaultOrgIdAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    private async Task<string> GetBootstrapOwnerEmailAsync()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE tenant_id = @orgId AND role = 'owner' LIMIT 1",
            new { orgId })
            ?? throw new InvalidOperationException("Bootstrap owner not found.");
    }
}
