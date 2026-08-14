using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management API for an org's alert email channel: /api/v1/alert-settings GET (the gate,
/// recipients and instanceEmailConfigured), the channel's own PUT /alert-settings/email, and
/// POST /alert-settings/email/test. The channel is the gate and the recipient list and nothing
/// else — SMTP is an instance-level transport, configured through /api/v1/instance/email-config —
/// so the retired per-org transport fields are asserted to be neither accepted nor projected.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AlertEmailSettingsTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public AlertEmailSettingsTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private static string NewMasterKey() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static async Task<HttpClient> AdminClient(DependablyFactory factory)
    {
        var client = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task Get_AbsentRow_ReturnsEmailDefaults()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("emailEnabled").GetBoolean());
        Assert.False(root.GetProperty("instanceEmailConfigured").GetBoolean());

        // The per-org transport is gone from the projection entirely, not merely defaulted.
        foreach (string retired in new[]
                 {
                     "emailInheritInstance", "hasEmailSmtpPassword", "emailSmtpHost", "emailSmtpPort",
                     "emailSmtpSecurity", "emailSmtpUsername", "emailSmtpFrom",
                     "emailSmtpCleartextCredentials",
                 })
        {
            Assert.False(root.TryGetProperty(retired, out _), $"{retired} should no longer be serialized");
        }
    }

    [Fact]
    public async Task PutEmail_GateAndRecipients_RoundTrip()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailEnabled = true,
            emailRecipients = "a@example.com, b@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/alert-settings");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("emailEnabled").GetBoolean());
        // Recipients are normalized (trimmed, rejoined without the original whitespace) on save.
        Assert.Equal("a@example.com,b@example.com", root.GetProperty("emailRecipients").GetString());
    }

    /// <summary>
    /// The retired per-org transport. The route exists again as the channel write, so the
    /// assertion is that a payload carrying the old transport fields is refused outright — the
    /// instance-wide JsonUnmappedMemberHandling.Disallow stance makes them unmapped members, so
    /// the write fails closed with a 400 instead of half-applying the channel half of the body
    /// and silently dropping the rest.
    /// </summary>
    [Fact]
    public async Task PutEmail_RetiredTransportFields_AreNotAccepted()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailEnabled = true,
            emailRecipients = "a@example.com",
            emailInheritInstance = false,
            emailSmtpHost = "smtp.example.com",
            emailSmtpPort = 587,
            emailSmtpUsername = "user",
            emailSmtpPassword = "secret",
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);

        // Nothing was written, and the projection still carries none of the retired transport.
        var get = await c.GetAsync("/api/v1/alert-settings");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("emailEnabled").GetBoolean());
        foreach (string retired in new[]
                 {
                     "emailInheritInstance", "hasEmailSmtpPassword", "emailSmtpHost", "emailSmtpPort",
                     "emailSmtpSecurity", "emailSmtpUsername", "emailSmtpFrom",
                     "emailSmtpCleartextCredentials",
                 })
        {
            Assert.False(root.TryGetProperty(retired, out _), $"{retired} should not be accepted or serialized");
        }

        // The instance transport is the only transport, and this org write did not configure one.
        Assert.False(root.GetProperty("instanceEmailConfigured").GetBoolean());
    }

    /// <summary>Mixed-validity list: one valid address plus one malformed one rejects the whole request.</summary>
    [Fact]
    public async Task PutEmail_MixedValidAndInvalidRecipients_RejectsWholeRequest()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailEnabled = true,
            emailRecipients = "valid@example.com,not-an-email",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/alert-settings");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("emailEnabled").GetBoolean());
    }

    [Fact]
    public async Task PutEmail_TooManyRecipients_Returns422()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        string recipients = string.Join(",", Enumerable.Range(0, 21).Select(i => $"u{i}@example.com"));
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailEnabled = true,
            emailRecipients = recipients,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task PutEmail_Member_Forbidden()
    {
        string id = await _factory.CreateUser($"aem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        using var c = _factory.CreateClientWithBearer(jwt);
        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new { emailEnabled = true });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Member_Get_Forbidden()
    {
        string id = await _factory.CreateUser($"aem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        using var c = _factory.CreateClientWithBearer(jwt);
        var resp = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }






    /// <summary>
    /// Three independent write surfaces — gates, email, Slack — each owning its own columns. The
    /// three saves are applied in turn and every one must leave the other two's columns intact,
    /// which is what lets the Alerts tab and the two Integrations sub-tabs be saved in any order.
    /// </summary>
    [Fact]
    public async Task GatesEmailAndSlackPuts_DoNotClobberEachOther()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var gatesPut = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "CRITICAL",
        });
        Assert.Equal(HttpStatusCode.OK, gatesPut.StatusCode);

        var emailPut = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailEnabled = true,
            emailRecipients = "admin@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, emailPut.StatusCode);

        // The email PUT must not have clobbered the gates.
        var emailDoc = JsonDocument.Parse(await emailPut.Content.ReadAsStringAsync()).RootElement;
        Assert.False(emailDoc.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", emailDoc.GetProperty("vulnMinSeverity").GetString());

        var slackPut = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T999/B999/mix",
        });
        Assert.Equal(HttpStatusCode.OK, slackPut.StatusCode);

        var doc = JsonDocument.Parse(await slackPut.Content.ReadAsStringAsync()).RootElement;
        Assert.False(doc.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.True(doc.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", doc.GetProperty("vulnMinSeverity").GetString());
        Assert.True(doc.GetProperty("slackEnabled").GetBoolean());
        Assert.True(doc.GetProperty("hasSlackWebhook").GetBoolean());
        // The Slack PUT must not have clobbered the email channel.
        Assert.True(doc.GetProperty("emailEnabled").GetBoolean());
        Assert.Equal("admin@example.com", doc.GetProperty("emailRecipients").GetString());

        // And a second gates save must leave both channels alone.
        var gatesPut2 = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = true,
            vulnAlertsEnabled = false,
            vulnMinSeverity = "LOW",
        });
        Assert.Equal(HttpStatusCode.OK, gatesPut2.StatusCode);
        var gatesDoc2 = JsonDocument.Parse(await gatesPut2.Content.ReadAsStringAsync()).RootElement;
        Assert.True(gatesDoc2.GetProperty("emailEnabled").GetBoolean());
        Assert.Equal("admin@example.com", gatesDoc2.GetProperty("emailRecipients").GetString());
        Assert.True(gatesDoc2.GetProperty("slackEnabled").GetBoolean());
        Assert.True(gatesDoc2.GetProperty("hasSlackWebhook").GetBoolean());
    }

    [Fact]
    public async Task Get_InstanceEmailConfigured_ReflectsInstanceConfigWithoutLeakingDetails()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "instance-smtp.example.com",
            port = 587,
            security = "none",
            username = (string?)null,
            password = (string?)null,
            fromAddress = "instance@example.com",
        });

        var get = await c.GetAsync("/api/v1/alert-settings");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        string body = await get.Content.ReadAsStringAsync();
        var root = JsonDocument.Parse(body).RootElement;

        Assert.True(root.GetProperty("instanceEmailConfigured").GetBoolean());
        Assert.DoesNotContain("instance-smtp.example.com", body);
        Assert.DoesNotContain("instance@example.com", body);
    }

    /// <summary>
    /// The connect-time regression this fix exists for: <c>emailSmtpHost</c> is a hostname, not
    /// an IP literal, so the save-time check never inspects it (by design — see
    /// <see cref="HostSsrfValidator"/>). Before this fix, <c>SmtpMailSender</c> handed the host
    /// straight to MailKit, which resolved and dialed it directly with no vetting at all — the
    /// relay could be pointed at any internal host:port. This listener stands in for that
    /// internal target: the test-send must still fail (nothing speaks SMTP on the far end), but
    /// on fixed code the connect-time guard refuses the resolved loopback address before any
    /// socket ever reaches the listener, so the listener's accept must never complete.
    /// </summary>
    [Fact]
    public async Task TestEmail_HostnameResolvingToBlockedAddress_NeverReachesTheTarget()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        try
        {
            var emailPut = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
            {
                emailEnabled = true,
                emailRecipients = "admin@example.com",
            });
            Assert.Equal(HttpStatusCode.OK, emailPut.StatusCode);

            var instancePut = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
            {
                enabled = true,
                host = "localhost",
                port,
                security = "none",
                username = (string?)null,
                password = (string?)null,
                fromAddress = "noreply@example.com",
            });
            Assert.Equal(HttpStatusCode.OK, instancePut.StatusCode);

            var resp = await c.PostAsync("/api/v1/alert-settings/email/test", content: null);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

            await Task.WhenAny(acceptTask, Task.Delay(TimeSpan.FromMilliseconds(500)));
            Assert.False(acceptTask.IsCompleted);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task TestEmail_NotConfigured_Returns422()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PostAsync("/api/v1/alert-settings/email/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// The org-level counterpart of <c>InstanceEmailConfigTests.Test_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage</c>:
    /// a test-send that fails to connect must return a generic 422 detail — never the raw
    /// MailKit/socket exception text. The org's own transport is seeded directly through
    /// <see cref="AlertSettingsRepository"/> (bypassing the PUT's host-literal SSRF check, which
    /// always blocks loopback) since the leak this test pins is on the send path, not the save
    /// path.
    /// </summary>
    [Fact]
    public async Task TestEmail_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        int deadPort;
        using (var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0))
        {
            probe.Start();
            deadPort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        }

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        await using (var conn = await store.OpenAsync())
        {
            orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
                ?? throw new InvalidOperationException("Default org not found.");
        }

        var envelope = factory.Services.GetRequiredService<Dependably.Infrastructure.Identity.EnvelopeProtector>();
        var settingsRepo = new AlertSettingsRepository(store, envelope, TimeProvider.System);
        await settingsRepo.UpdateEmailChannelAsync(orgId, new UpdateAlertEmailChannel(
            EmailEnabled: true, EmailRecipients: "admin@example.com"));

        // The transport is instance-level; the org contributes only the gate and recipients above.
        var orgs = factory.Services.GetRequiredService<OrgRepository>();
        await orgs.SetInstanceSettingAsync("smtp_enabled", "1");
        await orgs.SetInstanceSettingAsync("smtp_host", "127.0.0.1");
        await orgs.SetInstanceSettingAsync("smtp_port", deadPort.ToString(CultureInfo.InvariantCulture));
        await orgs.SetInstanceSettingAsync("smtp_security", "none");
        await orgs.SetInstanceSettingAsync("smtp_from_address", "noreply@example.com");
        factory.Services.GetRequiredService<InstanceSmtpConfig>().Invalidate();

        var resp = await c.PostAsync("/api/v1/alert-settings/email/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain(deadPort.ToString(), body);
        Assert.DoesNotContain("refused", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connect", body, StringComparison.OrdinalIgnoreCase);
    }
}
