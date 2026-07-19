using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management API for /api/v1/alert-settings: round-trip of the Alerts-tab columns (per-type
/// toggles, severity floor, email delivery gate + validated recipient list) via the base PUT,
/// the write-only Slack webhook URL (never echoed, only hasSlackWebhook) via the dedicated PUT
/// /alert-settings/slack, fail-closed behavior when no DEPENDABLY_MASTER_KEY is configured, and
/// that neither write surface clobbers the other's columns.
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
        // No DEPENDABLY_MASTER_KEY configured on the shared factory.
        Assert.False(root.GetProperty("secretsAvailable").GetBoolean());
    }

    [Fact]
    public async Task Put_TogglesSeverityAndEmailGate_RoundTrip()
    {
        using var c = await AdminClient();

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "CRITICAL",
            emailEnabled = true,
            emailRecipients = "a@example.com, b@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/alert-settings");
        var doc = await JsonDocument.ParseAsync(await get.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.False(root.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.True(root.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", root.GetProperty("vulnMinSeverity").GetString());
        Assert.True(root.GetProperty("emailEnabled").GetBoolean());
        // Recipients are normalized (trimmed, rejoined without the original whitespace) on save.
        Assert.Equal("a@example.com,b@example.com", root.GetProperty("emailRecipients").GetString());
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
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>Mixed-validity list: one valid address plus one malformed one rejects the whole request.</summary>
    [Fact]
    public async Task Put_MixedValidAndInvalidRecipients_RejectsWholeRequest()
    {
        await using var factory = new DependablyFactory();
        using var c = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            emailEnabled = true,
            emailRecipients = "valid@example.com,not-an-email",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/alert-settings");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("emailEnabled").GetBoolean());
    }

    [Fact]
    public async Task Put_TooManyRecipients_Returns422()
    {
        using var c = await AdminClient();

        string recipients = string.Join(",", Enumerable.Range(0, 21).Select(i => $"u{i}@example.com"));
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "HIGH",
            emailEnabled = true,
            emailRecipients = recipients,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task PutSlack_WithoutMasterKey_ReturnsValidationError()
    {
        // The shared factory runs with no DEPENDABLY_MASTER_KEY — storing a Slack URL must
        // fail closed with a clean 422, never an unhandled 500.
        using var c = await AdminClient();
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
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

    /// <summary>
    /// A test-send that fails — here, a loopback webhook URL that the connect-time SSRF guard
    /// rejects before any real socket I/O — must return a generic 422 detail, never the raw
    /// exception text (the guard's own message embeds the target host). The webhook URL is
    /// seeded directly through <see cref="AlertSettingsRepository"/> (bypassing the PUT's URL
    /// validator, which also blocks loopback) since the leak this test pins is on the send
    /// path, not the save path.
    /// </summary>
    [Fact]
    public async Task TestSlack_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var store = keyedFactory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
        }

        var envelope = keyedFactory.Services.GetRequiredService<Dependably.Infrastructure.Identity.EnvelopeProtector>();
        var settingsRepo = new AlertSettingsRepository(store, envelope, TimeProvider.System);
        await settingsRepo.UpdateSlackAsync(orgId, new UpdateAlertSlack(
            SlackEnabled: true, SlackWebhookUrl: "http://127.0.0.1/hook"));

        var resp = await c.PostAsync("/api/v1/alert-settings/slack/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain("blocked", body, StringComparison.OrdinalIgnoreCase);
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
    public async Task PutSlack_WebhookUrl_WithMasterKey_EncryptedAtRest_NeverEchoed()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var put = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
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
    public async Task PutSlack_EmptyWebhookUrl_LeavesExistingUrlUnchanged()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T222/B222/zzz",
        });

        // Update again with slackWebhookUrl omitted (null) and a different toggle value.
        var second = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = true,
            slackWebhookUrl = (string?)null,
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var doc = await JsonDocument.ParseAsync(await second.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("hasSlackWebhook").GetBoolean());
    }

    /// <summary>
    /// Mixed partial-failure style: saving the gates form must not clobber a previously-saved
    /// Slack configuration, and saving the Slack form must not clobber previously-saved gates —
    /// each PUT touches only its own columns.
    /// </summary>
    [Fact]
    public async Task GatesPut_And_SlackPut_DoNotClobberEachOther()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        // Save Slack first.
        var slackPut = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T333/B333/aaa",
        });
        Assert.Equal(HttpStatusCode.OK, slackPut.StatusCode);

        // Now save the gates — must not touch Slack.
        var gatesPut = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = false,
            vulnMinSeverity = "CRITICAL",
        });
        Assert.Equal(HttpStatusCode.OK, gatesPut.StatusCode);
        var gatesDoc = await JsonDocument.ParseAsync(await gatesPut.Content.ReadAsStreamAsync());
        Assert.False(gatesDoc.RootElement.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.False(gatesDoc.RootElement.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", gatesDoc.RootElement.GetProperty("vulnMinSeverity").GetString());
        Assert.True(gatesDoc.RootElement.GetProperty("slackEnabled").GetBoolean());
        Assert.True(gatesDoc.RootElement.GetProperty("hasSlackWebhook").GetBoolean());

        // Now save Slack again with different toggles — must not touch the gates just saved.
        var slackPut2 = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = false,
            slackWebhookUrl = (string?)null,
        });
        Assert.Equal(HttpStatusCode.OK, slackPut2.StatusCode);
        var slackDoc2 = await JsonDocument.ParseAsync(await slackPut2.Content.ReadAsStreamAsync());
        Assert.False(slackDoc2.RootElement.GetProperty("slackEnabled").GetBoolean());
        Assert.True(slackDoc2.RootElement.GetProperty("hasSlackWebhook").GetBoolean());
        Assert.False(slackDoc2.RootElement.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.False(slackDoc2.RootElement.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", slackDoc2.RootElement.GetProperty("vulnMinSeverity").GetString());
    }

    /// <summary>secretsAvailable mirrors EnvelopeProtector.IsConfigured on the GET projection.</summary>
    [Fact]
    public async Task Get_SecretsAvailable_ReflectsMasterKeyConfiguration()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var keyedFactory = new DependablyFactory { MasterKey = masterKey };
        using var c = keyedFactory.CreateClient();
        string jwt = await keyedFactory.CreateAdminJwt();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.True(doc.RootElement.GetProperty("secretsAvailable").GetBoolean());
    }
}
