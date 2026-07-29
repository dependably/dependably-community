using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the trust-anchor integrity audit:
/// <c>GET /api/v1/system/trust-anchors/suspect</c> plus the <c>trustAnchors.suspectCount</c>
/// field on <c>GET /api/v1/system/health</c>.
///
/// The rows under test cannot be created over HTTP — the add path refuses an unregistered
/// (ecosystem, anchorKind) pair — so they are seeded at the repository level, exactly as a
/// pre-validation insert left them in the table.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemSuspectTrustAnchorTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemSuspectTrustAnchorTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private const string Sentinel = "SENTINEL-MATERIAL-MUST-NOT-LEAK";

    private TrustAnchorRepository Repo => _factory.Services.GetRequiredService<TrustAnchorRepository>();

    // Creates a tenant through the system API and returns its org id.
    private async Task<(string OrgId, string Slug)> CreateTenantAsync(HttpClient client)
    {
        string slug = "sus-" + Guid.NewGuid().ToString("N")[..8];
        var resp = await client.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = @slug", new { slug }))!;
        return (orgId, slug);
    }

    [Fact]
    public async Task SystemAdmin_SeesSuspectRowsFromEveryTenant_AndNeverANormalRowOrItsMaterial()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var (orgA, slugA) = await CreateTenantAsync(client);
        var (orgB, slugB) = await CreateTenantAsync(client);

        var suspectA = await Repo.AddAsync(orgA, new NewTrustAnchor(
            "npm", "pgp", Sentinel, "kid-a", "pre-validation paste", "operator-1"));
        var suspectB = await Repo.AddAsync(orgB, new NewTrustAnchor(
            "nuget", "rsa", Sentinel, null, null, null));
        // Registered pair on the same tenant — must never appear in the audit.
        var normal = await Repo.AddAsync(orgB, new NewTrustAnchor(
            "apk", "rsa", "-----BEGIN PUBLIC KEY-----", "SHA256:ok", null, null));

        try
        {
            var resp = await client.GetAsync("/api/v1/system/trust-anchors/suspect");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            string body = await resp.Content.ReadAsStringAsync();

            // Regression guard: no material on this surface either, in any form.
            Assert.DoesNotContain(Sentinel, body, StringComparison.Ordinal);
            Assert.DoesNotContain("\"material\"", body, StringComparison.Ordinal);

            var items = JsonDocument.Parse(body).RootElement.GetProperty("items")
                .EnumerateArray().ToList();

            var a = items.Single(i => i.GetProperty("id").GetString() == suspectA.Id);
            Assert.Equal(orgA, a.GetProperty("orgId").GetString());
            Assert.Equal(slugA, a.GetProperty("orgSlug").GetString());
            Assert.Equal("npm", a.GetProperty("ecosystem").GetString());
            Assert.Equal("pgp", a.GetProperty("anchorKind").GetString());
            Assert.Equal("kid-a", a.GetProperty("keyId").GetString());
            Assert.Equal("pre-validation paste", a.GetProperty("label").GetString());
            Assert.Equal("operator-1", a.GetProperty("createdBy").GetString());
            Assert.NotEqual(default, a.GetProperty("createdAt").GetDateTimeOffset());

            var b = items.Single(i => i.GetProperty("id").GetString() == suspectB.Id);
            Assert.Equal(slugB, b.GetProperty("orgSlug").GetString());

            Assert.DoesNotContain(items, i => i.GetProperty("id").GetString() == normal.Id);

            // The health rollup counts them, and stays out of the overall severity.
            var health = await client.GetAsync("/api/v1/system/health");
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            var healthDoc = JsonDocument.Parse(await health.Content.ReadAsStringAsync()).RootElement;
            Assert.True(healthDoc.GetProperty("trustAnchors").GetProperty("suspectCount").GetInt32() >= 2);
        }
        finally
        {
            await Repo.DeleteAsync(orgA, suspectA.Id);
            await Repo.DeleteAsync(orgB, suspectB.Id);
            await Repo.DeleteAsync(orgB, normal.Id);
        }
    }

    [Fact]
    public async Task Anonymous_IsRefused()
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        var resp = await client.GetAsync("/api/v1/system/trust-anchors/suspect");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task TenantScopedSession_IsRefused()
    {
        // A tenant owner is fully authenticated but carries scope=tenant; RouteScopeFilter must
        // keep the cross-tenant audit out of reach. This is the adversarial twin of the
        // system-admin case above: the endpoint's whole value is that it crosses org boundaries,
        // so a tenant principal reaching it would be a BOLA hole rather than a feature.
        using var adminClient = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(adminClient);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        string userId;
        await using (var conn = await store.OpenAsync())
        {
            userId = (await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId LIMIT 1", new { orgId }))!;
        }

        string jwt = await _factory.CreateTenantJwt(userId, orgId);
        using var tenantClient = _factory.CreateClientForHost($"{slug}.localhost");
        tenantClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await tenantClient.GetAsync("/api/v1/system/trust-anchors/suspect");
        Assert.True(
            resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                or HttpStatusCode.NotFound,
            $"tenant-scoped session must not reach the cross-tenant audit, got {(int)resp.StatusCode}");
    }
}
