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
/// Management API for the per-org email SMTP transport: /api/v1/alert-settings GET (email block
/// + instanceEmailConfigured), PUT /alert-settings/email (transport-only — write-only password,
/// SSRF host posture; the delivery gate + recipients live on the base alert-settings PUT), and
/// POST /alert-settings/email/test.
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
        Assert.True(root.GetProperty("emailInheritInstance").GetBoolean());
        Assert.False(root.GetProperty("hasEmailSmtpPassword").GetBoolean());
        Assert.False(root.GetProperty("instanceEmailConfigured").GetBoolean());
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

    [Fact]
    public async Task PutEmail_WithoutMasterKey_PasswordRejected()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "smtp.example.com",
            emailSmtpPort = 587,
            emailSmtpSecurity = "starttls",
            emailSmtpUsername = "user",
            emailSmtpPassword = "super-secret",
            emailSmtpFrom = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task PutEmail_RoundTrip_PasswordNeverEchoed_HasPasswordFlips()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var put = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "smtp.example.com",
            emailSmtpPort = 587,
            emailSmtpSecurity = "starttls",
            emailSmtpUsername = "user",
            emailSmtpPassword = "super-secret",
            emailSmtpFrom = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        string putBody = await put.Content.ReadAsStringAsync();
        Assert.DoesNotContain("super-secret", putBody);
        var putRoot = JsonDocument.Parse(putBody).RootElement;
        Assert.True(putRoot.GetProperty("hasEmailSmtpPassword").GetBoolean());
        Assert.False(putRoot.TryGetProperty("emailSmtpPassword", out _));

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
        string? rawPassword = await conn.ExecuteScalarAsync<string>(
            "SELECT email_smtp_password FROM alert_settings WHERE org_id = @orgId", new { orgId });
        Assert.NotNull(rawPassword);
        Assert.StartsWith("enc:v1:", rawPassword);
    }

    [Fact]
    public async Task PutEmail_EmptyPassword_PreservesStoredSecret()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "smtp.example.com",
            emailSmtpPort = 587,
            emailSmtpSecurity = "starttls",
            emailSmtpUsername = "user",
            emailSmtpPassword = "original-secret",
            emailSmtpFrom = "noreply@example.com",
        });

        var second = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "smtp2.example.com",
            emailSmtpPort = 587,
            emailSmtpSecurity = "starttls",
            emailSmtpUsername = "user",
            emailSmtpPassword = "",
            emailSmtpFrom = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var root = JsonDocument.Parse(await second.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("hasEmailSmtpPassword").GetBoolean());
        Assert.Equal("smtp2.example.com", root.GetProperty("emailSmtpHost").GetString());
    }

    [Fact]
    public async Task PutEmail_BlockedSsrfHostLiteral_Returns422()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "169.254.169.254",
            emailSmtpPort = 587,
            emailSmtpSecurity = "none",
            emailSmtpFrom = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// An explicit JSON null for the security mode must come back as a clean client error, never
    /// a 500. Implicit required-property validation rejects it as 400 today; the controller also
    /// coalesces null to an invalid-security 422 as a backstop should that validation be relaxed.
    /// </summary>
    [Fact]
    public async Task PutEmail_ExplicitNullSecurity_IsClientErrorNot500()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = true,
            emailSmtpSecurity = (string?)null,
        });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    /// <summary>
    /// Three-way mixed partial-failure: gates, Slack, and email each PUT independently — none of
    /// the three writes clobbers the columns owned by either of the other two.
    /// </summary>
    [Fact]
    public async Task GatesSlackEmailPuts_DoNotClobberEachOther()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var gatesPut = await c.PutAsJsonAsync("/api/v1/alert-settings", new
        {
            quarantineAlertsEnabled = false,
            vulnAlertsEnabled = true,
            vulnMinSeverity = "CRITICAL",
            emailEnabled = true,
            emailRecipients = "admin@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, gatesPut.StatusCode);

        var slackPut = await c.PutAsJsonAsync("/api/v1/alert-settings/slack", new
        {
            slackEnabled = true,
            slackWebhookUrl = "https://hooks.slack.com/services/T999/B999/mix",
        });
        Assert.Equal(HttpStatusCode.OK, slackPut.StatusCode);

        var emailPut = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
        {
            emailInheritInstance = false,
            emailSmtpHost = "smtp.example.com",
            emailSmtpPort = 587,
            emailSmtpSecurity = "starttls",
            emailSmtpUsername = "user",
            emailSmtpPassword = "hunter2",
            emailSmtpFrom = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, emailPut.StatusCode);

        var doc = JsonDocument.Parse(await emailPut.Content.ReadAsStringAsync()).RootElement;
        Assert.False(doc.GetProperty("quarantineAlertsEnabled").GetBoolean());
        Assert.True(doc.GetProperty("vulnAlertsEnabled").GetBoolean());
        Assert.Equal("CRITICAL", doc.GetProperty("vulnMinSeverity").GetString());
        Assert.True(doc.GetProperty("slackEnabled").GetBoolean());
        Assert.True(doc.GetProperty("hasSlackWebhook").GetBoolean());
        // The transport PUT must not have clobbered the delivery gate saved by the gates PUT.
        Assert.True(doc.GetProperty("emailEnabled").GetBoolean());
        Assert.Equal("admin@example.com", doc.GetProperty("emailRecipients").GetString());
        Assert.True(doc.GetProperty("hasEmailSmtpPassword").GetBoolean());
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
    /// straight to MailKit, which resolved and dialed it directly with no vetting at all — an org
    /// admin could point the relay at any internal host:port. This listener stands in for that
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
            var gatesPut = await c.PutAsJsonAsync("/api/v1/alert-settings", new
            {
                emailEnabled = true,
                emailRecipients = "admin@example.com",
            });
            Assert.Equal(HttpStatusCode.OK, gatesPut.StatusCode);

            var emailPut = await c.PutAsJsonAsync("/api/v1/alert-settings/email", new
            {
                emailInheritInstance = false,
                emailSmtpHost = "localhost",
                emailSmtpPort = port,
                emailSmtpSecurity = "none",
                emailSmtpFrom = "noreply@example.com",
            });
            Assert.Equal(HttpStatusCode.OK, emailPut.StatusCode);

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
        await settingsRepo.UpdateGatesAsync(orgId, new UpdateAlertGates(
            QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH",
            EmailEnabled: true, EmailRecipients: "admin@example.com"));
        await settingsRepo.UpdateEmailAsync(orgId, new UpdateAlertEmail(
            EmailInheritInstance: false,
            EmailSmtpHost: "127.0.0.1",
            EmailSmtpPort: deadPort,
            EmailSmtpSecurity: "none",
            EmailSmtpUsername: null,
            EmailSmtpPassword: null,
            EmailSmtpFrom: "noreply@example.com"));

        var resp = await c.PostAsync("/api/v1/alert-settings/email/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain(deadPort.ToString(), body);
        Assert.DoesNotContain("refused", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connect", body, StringComparison.OrdinalIgnoreCase);
    }
}
