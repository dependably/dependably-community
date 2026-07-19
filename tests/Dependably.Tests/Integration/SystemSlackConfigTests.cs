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
/// Multi-mode coverage for <c>/api/v1/system/slack-config</c> (+ <c>/test</c>). Mirrors
/// <c>EmailConfigMultiModeTests</c>'s dual-surface conventions minus the dual surface itself —
/// operator Slack has no single-mode/instance counterpart (control-plane concept only).
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemSlackConfigTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemSlackConfigTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Get_AbsentRows_ReturnsDocumentedDefaults()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var resp = await client.GetAsync("/api/v1/system/slack-config");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.False(root.GetProperty("hasWebhook").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("lastDeliveryAt").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("lastStatus").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("lastError").ValueKind);
        Assert.False(root.GetProperty("secretsAvailable").GetBoolean());
    }

    [Fact]
    public async Task Put_WebhookWithoutMasterKey_Returns422()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var resp = await client.PutAsJsonAsync("/api/v1/system/slack-config", new
        {
            enabled = true,
            webhookUrl = "https://hooks.slack.com/services/T00/B00/xxx",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Put_RoundTrip_UrlNeverEchoed_HasWebhookFlips_EncryptedAtRest()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var put = await client.PutAsJsonAsync("/api/v1/system/slack-config", new
        {
            enabled = true,
            webhookUrl = "https://hooks.slack.com/services/T00/B00/xxx",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        string putBody = await put.Content.ReadAsStringAsync();
        Assert.DoesNotContain("hooks.slack.com", putBody);
        var putRoot = JsonDocument.Parse(putBody).RootElement;
        Assert.True(putRoot.GetProperty("hasWebhook").GetBoolean());
        Assert.False(putRoot.TryGetProperty("webhookUrl", out _));

        var get = await client.GetAsync("/api/v1/system/slack-config");
        string getBody = await get.Content.ReadAsStringAsync();
        Assert.DoesNotContain("hooks.slack.com", getBody);
        var getRoot = JsonDocument.Parse(getBody).RootElement;
        Assert.True(getRoot.GetProperty("enabled").GetBoolean());
        Assert.True(getRoot.GetProperty("hasWebhook").GetBoolean());

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? raw = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'system_slack_webhook_url' LIMIT 1");
        Assert.NotNull(raw);
        Assert.StartsWith("enc:v1:", raw);
    }

    [Fact]
    public async Task Put_EmptyWebhookUrl_PreservesStoredSecret()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        await client.PutAsJsonAsync("/api/v1/system/slack-config", new
        {
            enabled = true,
            webhookUrl = "https://hooks.slack.com/services/T00/B00/original",
        });

        // Second PUT with an empty URL and enabled flipped off — the enabled flag must land,
        // the URL must be preserved (mixed partial-failure-style: one field changes, one doesn't).
        var second = await client.PutAsJsonAsync("/api/v1/system/slack-config", new
        {
            enabled = false,
            webhookUrl = "",
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var root = JsonDocument.Parse(await second.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("hasWebhook").GetBoolean());
        Assert.False(root.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task Test_NotConfigured_Returns422()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var resp = await client.PostAsync("/api/v1/system/slack-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// A test-send that fails — here, a loopback webhook URL that the connect-time SSRF guard
    /// rejects before any real socket I/O — must return a generic 422 detail, never the raw
    /// exception text (the guard's own message embeds the target host). The webhook URL is
    /// seeded directly through <see cref="OrgRepository.SetInstanceSettingAsync"/> (bypassing
    /// the PUT's URL validator, which also blocks loopback) since the leak this test pins is on
    /// the send path, not the save path.
    /// </summary>
    [Fact]
    public async Task Test_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var orgs = factory.Services.GetRequiredService<OrgRepository>();
        await orgs.SetInstanceSettingAsync("system_slack_enabled", "1");
        await orgs.SetInstanceSettingAsync("system_slack_webhook_url", "http://127.0.0.1/hook");

        var resp = await client.PostAsync("/api/v1/system/slack-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain("blocked", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Put_AuditsNonSecretFieldsOnly()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        await client.PutAsJsonAsync("/api/v1/system/slack-config", new
        {
            enabled = true,
            webhookUrl = "https://hooks.slack.com/services/T00/B00/xxx",
        });

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'system_admin.slack_config_updated' ORDER BY rowid DESC LIMIT 1");
        Assert.NotNull(detail);
        Assert.DoesNotContain("hooks.slack.com", detail);
        Assert.Contains("webhookRotated", detail);
    }

    // ── Realm gating ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TenantOwner_GetSlackConfig_Returns404()
    {
        string slug = "ssc-" + Guid.NewGuid().ToString("N")[..8];
        using var sysClient = await _factory.CreateSystemAdminClient();
        var createResp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, createResp.StatusCode);
        var createDoc = JsonDocument.Parse(await createResp.Content.ReadAsStringAsync());
        string tenantId = createDoc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;

        string ownerId;
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1", new { tenantId })
                ?? throw new InvalidOperationException("owner user missing");
        }

        string jwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/system/slack-config");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
