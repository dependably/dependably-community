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
/// Single-tenant mode coverage for <c>/api/v1/instance/email-config</c> (+ <c>/test</c>).
/// Mirrors the metrics-access dual-surface tests: shared validation/response shaping via
/// <c>EmailConfigEditing</c>, write-only password, and the multi-mode 404 gate covered
/// separately below.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceEmailConfigTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public InstanceEmailConfigTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<HttpClient> AdminClient(DependablyFactory factory)
    {
        // CreateClient() triggers WebApplicationFactory host startup (schema init + first
        // boot); it must run before CreateAdminJwt() reads the seeded default org/owner.
        var client = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task Member_Get_Returns403()
    {
        string memberId = await _factory.CreateUser($"emc-mem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/email-config");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Get_AbsentRows_ReturnsDocumentedDefaults()
    {
        // Own factory: the shared _factory's instance_settings may already carry smtp_* rows
        // written by another test in this class fixture (xUnit does not guarantee method order).
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.GetAsync("/api/v1/instance/email-config");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.Equal(587, root.GetProperty("port").GetInt32());
        Assert.Equal("starttls", root.GetProperty("security").GetString());
        Assert.False(root.GetProperty("hasPassword").GetBoolean());
        Assert.False(root.GetProperty("configured").GetBoolean());
        Assert.False(root.GetProperty("secretsAvailable").GetBoolean());
    }

    [Fact]
    public async Task Put_PasswordWithoutMasterKey_Returns422()
    {
        // The shared factory runs with no DEPENDABLY_MASTER_KEY.
        using var c = await AdminClient(_factory);

        var resp = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 587,
            security = "starttls",
            username = "user",
            password = "super-secret",
            fromAddress = "noreply@example.com",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Put_InvalidSecurity_Returns422_AndWritesNothing()
    {
        // Mixed-validity request: host/port/from are all valid, security alone is bogus.
        // Validation must reject the whole PUT before any instance_settings row is touched —
        // a subsequent GET must still show the pre-existing (or default) state, not a partial
        // application of the valid fields.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 587,
            security = "not-a-real-mode",
            username = "user",
            password = (string?)null,
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/instance/email-config");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.Null(root.GetProperty("host").GetString());
    }

    [Fact]
    public async Task Put_RoundTrip_PasswordNeverEchoed_HasPasswordFlips()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyFactory { MasterKey = masterKey };
        using var c = await AdminClient(factory);

        var put = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 465,
            security = "ssl",
            username = "user",
            password = "super-secret",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        string putBody = await put.Content.ReadAsStringAsync();
        Assert.DoesNotContain("super-secret", putBody);
        var putRoot = JsonDocument.Parse(putBody).RootElement;
        Assert.True(putRoot.GetProperty("hasPassword").GetBoolean());
        Assert.True(putRoot.GetProperty("configured").GetBoolean());
        Assert.False(putRoot.TryGetProperty("password", out _));

        var get = await c.GetAsync("/api/v1/instance/email-config");
        string getBody = await get.Content.ReadAsStringAsync();
        Assert.DoesNotContain("super-secret", getBody);
        var getRoot = JsonDocument.Parse(getBody).RootElement;
        Assert.Equal("smtp.example.com", getRoot.GetProperty("host").GetString());
        Assert.Equal(465, getRoot.GetProperty("port").GetInt32());
        Assert.Equal("ssl", getRoot.GetProperty("security").GetString());
        Assert.True(getRoot.GetProperty("hasPassword").GetBoolean());

        // The stored value is envelope-encrypted at rest.
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? rawPassword = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'smtp_password' LIMIT 1");
        Assert.NotNull(rawPassword);
        Assert.StartsWith("enc:v1:", rawPassword);
    }

    [Fact]
    public async Task Put_EmptyPassword_PreservesStoredSecret()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyFactory { MasterKey = masterKey };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 587,
            security = "starttls",
            username = "user",
            password = "original-secret",
            fromAddress = "noreply@example.com",
        });

        // Second PUT with an empty password and a changed host — the host change must land,
        // the password must be preserved.
        var second = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp2.example.com",
            port = 587,
            security = "starttls",
            username = "user",
            password = "",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var root = JsonDocument.Parse(await second.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("hasPassword").GetBoolean());
        Assert.Equal("smtp2.example.com", root.GetProperty("host").GetString());
    }

    [Fact]
    public async Task Test_NotConfigured_Returns422()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PostAsync("/api/v1/instance/email-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// Regression: before this fix, PUT /api/v1/instance/email-config had no SSRF check on
    /// <c>host</c> at all (not even the IP-literal check the per-org alert email transport has
    /// always had) — a tenant owner could point the instance SMTP relay at the cloud metadata
    /// endpoint and it would be accepted outright.
    /// </summary>
    [Fact]
    public async Task Put_BlockedSsrfHostLiteral_Returns422()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "169.254.169.254",
            port = 587,
            security = "none",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var get = await c.GetAsync("/api/v1/instance/email-config");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.Null(root.GetProperty("host").GetString());
    }

    /// <summary>
    /// A test-send that fails to connect must return a generic 422 detail — never the raw
    /// MailKit/socket/SSRF-guard exception text. That text carries the caller-controlled
    /// host/port itself (and, pre-fix, the connect-vs-handshake-vs-timeout distinction), which is
    /// an internal-network probe surface for whoever can reach this admin-only endpoint.
    /// Regression for the info-leak fixed alongside this test: the failure detail is logged
    /// server-side and the response body carries only a fixed resource string. The host is a
    /// hostname ("localhost"), not the "127.0.0.1" IP literal — the write-time SSRF check would
    /// reject a loopback literal outright, and this test's failure mode is deliberately the
    /// connect-time SSRF guard, not a save-time rejection.
    /// </summary>
    [Fact]
    public async Task Test_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage()
    {
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        int deadPort;
        using (var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0))
        {
            probe.Start();
            deadPort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        }

        var put = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "localhost",
            port = deadPort,
            security = "none",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var resp = await c.PostAsync("/api/v1/instance/email-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("localhost", body);
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain(deadPort.ToString(), body);
        Assert.DoesNotContain("refused", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connect", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Put_AuditsNonSecretFieldsOnly()
    {
        string masterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        await using var factory = new DependablyFactory { MasterKey = masterKey };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 587,
            security = "starttls",
            username = "user",
            password = "super-secret",
            fromAddress = "noreply@example.com",
        });

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'instance_email_config_updated' ORDER BY rowid DESC LIMIT 1");
        Assert.NotNull(detail);
        Assert.DoesNotContain("super-secret", detail);
        Assert.Contains("smtp.example.com", detail);
    }

    // ── Single mode: apex/system routes are unreachable ──────────────────────

    [Fact]
    public async Task SingleMode_TenantAdmin_GetSystemEmailConfig_Returns404()
    {
        using var c = await AdminClient(_factory);
        var resp = await c.GetAsync("/api/v1/system/email-config");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}

/// <summary>
/// Multi-tenant mode coverage: a tenant owner (even with <c>tenant:admin</c>) must receive 404
/// on <c>/api/v1/instance/email-config</c> — email config is a control-plane concern owned by
/// the operator in multi mode. The system-realm equivalent remains reachable for system_admin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EmailConfigMultiModeTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public EmailConfigMultiModeTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string ownerJwt, string tenantHost)> CreateTenantOwnerAsync()
    {
        string slug = "emc-" + Guid.NewGuid().ToString("N")[..8];
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
        await using (var conn = await _factory.Services
            .GetRequiredService<IMetadataStore>().OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @tenantId LIMIT 1",
                new { tenantId })
                ?? throw new InvalidOperationException("owner user missing");

            // Clear the first-boot must_change_password flag so PasswordRotationGuard doesn't
            // intercept the request with 403 before the controller gate is reached.
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @ownerId",
                new { ownerId });
        }

        string jwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        return (jwt, host);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetEmailConfig_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/email-config");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_PutEmailConfig_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PutAsJsonAsync("/api/v1/instance/email-config", new { enabled = true });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── System-realm surface (apex, system_admin) ────────────────────────────

    [Fact]
    public async Task SystemAdmin_Get_ReturnsDocumentedDefaultsShape()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync("/api/v1/system/email-config");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("enabled").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(root.GetProperty("hasPassword").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.False(root.TryGetProperty("password", out _));
    }

    [Fact]
    public async Task SystemAdmin_Put_PasswordWithoutMasterKey_Returns422()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var resp = await client.PutAsJsonAsync("/api/v1/system/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 587,
            security = "starttls",
            username = "user",
            password = "super-secret",
            fromAddress = "noreply@example.com",
        });

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAdmin_Test_NotConfigured_Returns422()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PostAsync("/api/v1/system/email-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// System-realm counterpart of <c>InstanceEmailConfigTests.Put_BlockedSsrfHostLiteral_Returns422</c>:
    /// PUT /api/v1/system/email-config previously had no SSRF check on <c>host</c> at all.
    /// </summary>
    [Fact]
    public async Task SystemAdmin_Put_BlockedSsrfHostLiteral_Returns422()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var resp = await client.PutAsJsonAsync("/api/v1/system/email-config", new
        {
            enabled = true,
            host = "169.254.169.254",
            port = 587,
            security = "none",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    /// <summary>
    /// The system-realm counterpart of <c>InstanceEmailConfigTests.Test_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage</c>:
    /// a test-send that fails to connect must return a generic 422 detail — never the raw
    /// MailKit/socket/SSRF-guard exception text (which embeds the caller-controlled host/port) —
    /// on <c>POST /api/v1/system/email-config/test</c>. The host is a hostname ("localhost"), not
    /// the "127.0.0.1" IP literal, so the failure comes from the connect-time SSRF guard rather
    /// than the save-time literal check.
    /// </summary>
    [Fact]
    public async Task SystemAdmin_Test_SendFailure_ReturnsGenericDetail_NeverRawExceptionMessage()
    {
        await using var factory = new DependablyMultiFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        int deadPort;
        using (var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0))
        {
            probe.Start();
            deadPort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        }

        var put = await client.PutAsJsonAsync("/api/v1/system/email-config", new
        {
            enabled = true,
            host = "localhost",
            port = deadPort,
            security = "none",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var resp = await client.PostAsync("/api/v1/system/email-config/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        string body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("localhost", body);
        Assert.DoesNotContain("127.0.0.1", body);
        Assert.DoesNotContain(deadPort.ToString(), body);
        Assert.DoesNotContain("refused", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connect", body, StringComparison.OrdinalIgnoreCase);
    }
}
