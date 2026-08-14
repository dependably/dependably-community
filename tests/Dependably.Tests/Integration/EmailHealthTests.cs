using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Single-tenant mode coverage for <c>/api/v1/instance/email-health</c> — the operator's aggregate
/// relay-health surface. Gated the same as its <c>email-config</c> sibling
/// (<c>tenant:configure</c>, 404 in multi mode); the multi-mode/system-realm counterpart is covered
/// in <see cref="EmailHealthMultiModeTests"/>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceEmailHealthTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public InstanceEmailHealthTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<HttpClient> AdminClient(DependablyFactory factory)
    {
        var client = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task Member_Get_Returns403()
    {
        string memberId = await _factory.CreateUser($"eh-mem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/email-health");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Get_NoFailures_ReturnsHealthy()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.GetAsync("/api/v1/instance/email-health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("unhealthy").GetBoolean());
        Assert.Equal(0, root.GetProperty("affectedTenants").GetInt32());
        Assert.Equal(0, root.GetProperty("consecutiveFailures").GetInt32());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("firstFailureAt").ValueKind);
        Assert.Equal(0, root.GetProperty("backlogDepth").GetInt32());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("oldestQueuedAt").ValueKind);
        Assert.Equal(0, root.GetProperty("deadLettered").GetInt32());
        Assert.Equal(0, root.GetProperty("expired").GetInt32());
    }

    /// <summary>
    /// Drives a real delivery failure through <see cref="AlertSettingsRepository"/> (the same
    /// write path <c>EmailOutboxDeliveryService</c> uses) and asserts the aggregate reflects it —
    /// pinning both the arithmetic end to end through the HTTP surface and the exact camelCase
    /// JSON property names the frontend reads.
    /// </summary>
    [Fact]
    public async Task Get_WithFailures_ReturnsUnhealthyAggregate()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var envelope = new EnvelopeProtector(new EnvFileMasterKeyProvider(
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPENDABLY_MASTER_KEY"] = masterKey })
                .Build()));

        string orgId;
        await using (var conn = await factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
        }

        var settings = new AlertSettingsRepository(
            factory.Services.GetRequiredService<IMetadataStore>(), envelope,
            factory.Services.GetRequiredService<TimeProvider>());
        await settings.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "ops@example.com"));
        await settings.RecordEmailFailureAsync(orgId, "relay refused connection");
        await settings.RecordEmailFailureAsync(orgId, "relay refused connection");

        var resp = await c.GetAsync("/api/v1/instance/email-health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("unhealthy").GetBoolean());
        Assert.Equal(1, root.GetProperty("affectedTenants").GetInt32());
        Assert.Equal(2, root.GetProperty("consecutiveFailures").GetInt32());
        Assert.NotEqual(JsonValueKind.Null, root.GetProperty("firstFailureAt").ValueKind);
    }

    [Fact]
    public async Task SingleMode_TenantAdmin_GetSystemEmailHealth_Returns404()
    {
        using var c = await AdminClient(_factory);
        var resp = await c.GetAsync("/api/v1/system/email-health");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}

/// <summary>
/// Multi-tenant mode coverage: a tenant owner must get 404 on the single-mode
/// <c>/api/v1/instance/email-health</c> route — relay health is a control-plane concern in multi
/// mode. The system-realm equivalent is reachable only to <c>system_admin</c>; a fully-authenticated
/// tenant session (even <c>tenant:admin</c>) is the negative twin proving the cross-tenant
/// aggregate cannot be read from the data plane.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EmailHealthMultiModeTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public EmailHealthMultiModeTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string TenantId, string OwnerId, string OwnerJwt, string Host)> CreateTenantOwnerAsync(
        DependablyMultiFactory factory)
    {
        string slug = "eh-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);

        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string tenantId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        string ownerId;
        await using (var conn = await factory.Services
            .GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1",
                new { tenantId })
                ?? throw new InvalidOperationException("owner user missing");

            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @ownerId",
                new { ownerId });
        }

        string jwt = await factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        return (tenantId, ownerId, jwt, host);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetInstanceEmailHealth_Returns404()
    {
        var (_, _, jwt, host) = await CreateTenantOwnerAsync(_factory);
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/email-health");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    /// <summary>
    /// The negative twin of <see cref="SystemAdmin_Get_ReturnsHealthyDefault"/>: a fully
    /// authenticated tenant owner session (the highest-privilege tenant role) hitting the apex-only
    /// aggregate route must not read it. <c>RouteScopeFilter</c> pins <c>/api/v1/system/</c> to
    /// <c>scope=system</c>, so the failure mode is 404 (route not found for this session's scope),
    /// matching the posture pinned for every other apex-only route in this repo.
    /// </summary>
    [Fact]
    public async Task MultiMode_TenantOwner_GetSystemEmailHealth_Returns404()
    {
        var (_, _, jwt, host) = await CreateTenantOwnerAsync(_factory);
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/system/email-health");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAdmin_Get_ReturnsHealthyDefault()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/email-health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("unhealthy").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(root.GetProperty("affectedTenants").GetInt32() >= 0);
    }

    /// <summary>
    /// The cross-tenant aggregate case: two distinct tenants failing must both be counted, and
    /// neither tenant's slug or id appears anywhere in the response — the control-plane-safe shape
    /// this surface is required to keep in multi mode.
    /// </summary>
    [Fact]
    public async Task SystemAdmin_Get_AggregatesAcrossMultipleTenants_NeverNamesATenant()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        var (tenant1, _, _, _) = await CreateTenantOwnerAsync(factory);
        var (tenant2, _, _, _) = await CreateTenantOwnerAsync(factory);

        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var envelope = new EnvelopeProtector(new EnvFileMasterKeyProvider(
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPENDABLY_MASTER_KEY"] = masterKey })
                .Build()));
        var settings = new AlertSettingsRepository(
            factory.Services.GetRequiredService<IMetadataStore>(), envelope,
            factory.Services.GetRequiredService<TimeProvider>());

        string tenant1Slug, tenant2Slug;
        await using (var conn = await factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            tenant1Slug = await conn.ExecuteScalarAsync<string>(
                "SELECT slug FROM orgs WHERE id = @id", new { id = tenant1 }) ?? "";
            tenant2Slug = await conn.ExecuteScalarAsync<string>(
                "SELECT slug FROM orgs WHERE id = @id", new { id = tenant2 }) ?? "";
        }

        foreach (string tenantId in new[] { tenant1, tenant2 })
        {
            await settings.UpdateEmailChannelAsync(tenantId, new UpdateAlertEmailChannel(
                EmailEnabled: true, EmailRecipients: "ops@example.com"));
            await settings.RecordEmailFailureAsync(tenantId, "relay refused connection");
        }

        using var client = await factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/email-health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        var root = JsonDocument.Parse(body).RootElement;
        Assert.True(root.GetProperty("unhealthy").GetBoolean());
        Assert.Equal(2, root.GetProperty("affectedTenants").GetInt32());

        Assert.DoesNotContain(tenant1, body, StringComparison.Ordinal);
        Assert.DoesNotContain(tenant2, body, StringComparison.Ordinal);
        Assert.DoesNotContain(tenant1Slug, body, StringComparison.Ordinal);
        Assert.DoesNotContain(tenant2Slug, body, StringComparison.Ordinal);
    }
}
