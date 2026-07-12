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
/// Management API for /api/v1/alert-settings: round-trip of the per-type toggles and severity
/// floor, write-only Slack webhook URL (never echoed, only hasSlackWebhook), and fail-closed
/// behavior when no DEPENDABLY_MASTER_KEY is configured.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertSettingsTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AlertSettingsTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        return _factory.CreateClientWithBearer(jwt);
    }

    [Fact]
    public async Task Get_AbsentRow_ReturnsDocumentedDefaults()
    {
        // Own factory (own database): the shared _factory's default org may already have an
        // alert_settings row written by another test in this class (xUnit does not guarantee
        // method order), which would defeat the "absent row" precondition this test needs.
        await using var factory = new DependablyFactory();
        using var c = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.True(root.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.True(root.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("HIGH", root.GetProperty("vulnMinSeverity").GetString());
        Assert.False(root.GetProperty("slackEnabled").GetBoolean());
        Assert.False(root.GetProperty("hasSlackWebhook").GetBoolean());
    }

    [Fact]
    public async Task Put_TogglesAndSeverity_RoundTrip()
    {
        using var c = await AdminClient();

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "CRITICAL",
            slackEnabled = false,
            slackWebhookUrl = (string?)null,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/alert-settings");
        var doc = await JsonDocument.ParseAsync(await get.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.False(root.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.True(root.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", root.GetProperty("vulnMinSeverity").GetString());
    }

    [Fact]
    public async Task Put_InvalidSeverity_ReturnsValidationError()
    {
        using var c = await AdminClient();
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "SUPER_HIGH",
            slackEnabled = false,
            slackWebhookUrl = (string?)null,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Put_SlackWebhookUrlWithoutMasterKey_ReturnsValidationError()
    {
        // The shared factory runs with no DEPENDABLY_MASTER_KEY — storing a Slack URL must
        // fail closed with a clean 422, never an unhandled 500.
        using var c = await AdminClient();
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T000/B000/xxx",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task TestSlack_NotConfigured_ReturnsValidationError()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsync("/api/v1/alert-settings/slack/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Member_Get_Forbidden()
    {
        string id = await _factory.CreateUser($"asmem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        using var c = _factory.CreateClientWithBearer(jwt);
        var resp = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    /// <summary>
    /// With a master key configured, the Slack webhook URL round-trips as encrypted at rest
    /// (enc:v1: prefix) and is never echoed back — only hasSlackWebhook flips true.
    /// </summary>
    [Fact]
    public async Task Put_SlackWebhookUrl_WithMasterKey_EncryptedAtRest_NeverEchoed()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var put = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T111/B111/yyy",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var putDoc = await JsonDocument.ParseAsync(await put.Content.ReadAsStreamAsync());
        Assert.True(putDoc.RootElement.GetProperty("hasSlackWebhook").GetBoolean());
        // The response never carries a slackWebhookUrl property at all — write-only.
        Assert.False(putDoc.RootElement.TryGetProperty("slackWebhookUrl", out _));

        var store = keyedFactory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        string? rawUrl = await conn.ExecuteScalarAsync<string>(
            "SELECT slack_webhook_url FROM alert_settings WHERE org_id = @orgId", new { orgId });
        Assert.NotNull(rawUrl);
        Assert.StartsWith("enc:v1:", rawUrl);
    }

    /// <summary>An empty/absent slackWebhookUrl on update leaves the previously stored URL unchanged.</summary>
    [Fact]
    public async Task Put_EmptySlackWebhookUrl_LeavesExistingUrlUnchanged()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T222/B222/zzz",
        });

        // Update again with slackWebhookUrl omitted (null) and a different toggle value.
        var second = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            slackEnabled = true,
            slackWebhookUrl = (string?)null,
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var doc = await JsonDocument.ParseAsync(await second.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("hasSlackWebhook").GetBoolean());
    }
}
