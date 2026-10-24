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
/// Single-tenant mode coverage for /api/v1/instance/settings and
/// /api/v1/instance/background-jobs. In single mode the tenant's admins are also the operators, so
/// these routes must remain accessible to both admin and owner — they are gated on
/// tenant:configure, which both roles hold, not on the owner-only tenant:admin.
///
/// Note CreateAdminJwt mints the bootstrap *owner*, so the Admin_* tests below exercise the owner
/// path. The RoleAdmin_* tests are what actually pin a non-owner admin's access.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public InstanceControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task Anonymous_Get_Returns401Or404()
    {
        using var c = _factory.CreateClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.True(resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Member_Get_Returns403()
    {
        // tenant:configure is held by admin and owner; a plain member is rejected even though
        // authenticated.
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── Non-owner admin access ────────────────────────────────────────────────
    //
    // In single mode the org is the deployment, so an admin — who already configures the block
    // gates, licence enforcement, trust anchors and proxy upstreams — also administers the
    // instance. These pin that a genuine `admin` role (not the bootstrap owner CreateAdminJwt
    // returns) reaches every instance route.

    // The role must be persisted on the user row, not just claimed on the JWT: OrgAccessGuard
    // resolves capabilities from the stored role, so a token claiming "admin" over a member row is
    // correctly refused.
    private async Task<HttpClient> RoleAdminClient()
    {
        string userId = await _factory.CreateUser(
            $"roleadmin-{Guid.NewGuid():N}@example.com", "Password12345", role: "admin");
        string jwt = await _factory.CreateUserJwt(userId, "admin");
        return _factory.CreateClientWithBearer(jwt);
    }

    [Fact]
    public async Task RoleAdmin_GetSettings_Returns200()
    {
        using var c = await RoleAdminClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RoleAdmin_UpdateSettings_Persists()
    {
        using var c = await RoleAdminClient();

        var put = await c.PutAsJsonAsync("/api/v1/instance/settings", new Dictionary<string, string>
        {
            ["MAX_UPLOAD_BYTES"] = "12345678"
        });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var get = await c.GetAsync("/api/v1/instance/settings");
        var root = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("12345678", root.GetProperty("MAX_UPLOAD_BYTES").GetString());
    }

    [Fact]
    public async Task RoleAdmin_GetEmailConfig_Returns200()
    {
        using var c = await RoleAdminClient();
        var resp = await c.GetAsync("/api/v1/instance/email-config");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task RoleAdmin_GetBackgroundJobs_Returns200()
    {
        using var c = await RoleAdminClient();
        var resp = await c.GetAsync("/api/v1/instance/background-jobs");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    /// <summary>
    /// The widest of the instance routes: this allowlist is what stands between the public and
    /// /metrics, /version and the management docs. It is deliberately gated the same as its
    /// siblings rather than carved out as owner-only, so an admin can edit it — pinned here so the
    /// decision is visible rather than incidental.
    /// </summary>
    [Fact]
    public async Task RoleAdmin_PutMetricsAccess_Persists()
    {
        using var c = await RoleAdminClient();

        var put = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new
        {
            enabled = true,
            allowedIps = new[] { "10.9.9.0/24" },
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var get = await c.GetAsync("/api/v1/instance/metrics-access");
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        var ips = JsonDocument.Parse(await get.Content.ReadAsStringAsync())
            .RootElement.GetProperty("allowedIps").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("10.9.9.0/24", ips);
    }

    [Fact]
    public async Task Admin_GetSettings_Returns200WithDictionary_AndOmitsJwtSecret()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/instance/settings");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);

        // jwt_secret is filtered from the public response — checking the field is missing
        // pins that the controller never accidentally surfaces it.
        Assert.False(doc.RootElement.TryGetProperty("jwt_secret", out _));
    }

    [Fact]
    public async Task Admin_UpdateSettings_PersistsAndAudits()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "1048576",
            ["max_upload_bytes_npm"] = "524288",
        });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Verify the rows landed.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? value = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes' LIMIT 1");
        Assert.Equal("1048576", value);

        // Audit row recorded for the change.
        long audited = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'instance_settings_updated'");
        Assert.True(audited >= 1);
    }

    [Fact]
    public async Task Admin_UpdateSettings_RejectsUnknownKey()
    {
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string> { ["totally_unknown"] = "nope" });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        string detail = await resp.Content.ReadAsStringAsync();
        Assert.Contains("totally_unknown", detail);
    }

    [Fact]
    public async Task Admin_UpdateSettings_AcceptsReconciledKeys()
    {
        // default_storage_quota_bytes + max_active_tokens_per_tenant were previously rejected
        // in single mode (the InstanceController key set had drifted behind the system surface).
        // After the canonical-key-set reconcile both are accepted here too.
        using var c = await AdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["default_storage_quota_bytes"] = "1073741824",
            ["max_active_tokens_per_tenant"] = "250",
            ["max_upload_bytes_oci"] = "2147483648",
        });

        var resp = await c.PutAsync("/api/v1/instance/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
    }

    // ── /metrics access ──────────────────────────────────────────────────────

    [Fact]
    public async Task Member_GetMetricsAccess_Returns403()
    {
        string memberId = await _factory.CreateUser($"member-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync("/api/v1/instance/metrics-access");
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_GetMetricsAccess_ReturnsValidShape()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync("/api/v1/instance/metrics-access");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(json.GetProperty("enabled").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.Contains(json.GetProperty("allowlistSource").GetString(), new[] { "env", "db", "default" });
        Assert.True(json.GetProperty("allowedIps").GetArrayLength() > 0);
    }

    [Fact]
    public async Task Admin_PutMetricsAccess_PersistsReflectsInGetAndAudits()
    {
        using var c = await AdminClient();

        var put = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new
        {
            enabled = true,
            allowedIps = new[] { "10.0.0.0/8", "::1" },
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var get = await c.GetAsync("/api/v1/instance/metrics-access");
        var json = JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("db", json.GetProperty("allowlistSource").GetString());
        var ips = json.GetProperty("allowedIps").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains("10.0.0.0/8", ips);

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        long audited = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'instance_metrics_access_updated'");
        Assert.True(audited >= 1);
    }

    [Fact]
    public async Task Admin_PutMetricsAccess_MalformedCidr_RejectedWith4xx()
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new
        {
            allowedIps = new[] { "not-an-ip" },
        });
        Assert.True((int)put.StatusCode is >= 400 and < 500, $"Expected client error, got {put.StatusCode}");
    }

    [Fact]
    public async Task Admin_PutMetricsAccess_BroadCidr_ReturnsWarning()
    {
        using var c = await AdminClient();
        var put = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new
        {
            allowedIps = new[] { "0.0.0.0/0" },
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var warnings = JsonDocument.Parse(await put.Content.ReadAsStringAsync())
            .RootElement.GetProperty("warnings").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Single(warnings);
        Assert.Contains("0.0.0.0/0", warnings[0]!);
    }

    // ── Capability denials, env locks, and the email test send ───────────────

    [Theory]
    [InlineData("GET", "/api/v1/instance/settings", null)]
    [InlineData("PUT", "/api/v1/instance/settings", """{"max_upload_bytes":"1"}""")]
    [InlineData("GET", "/api/v1/instance/metrics-access", null)]
    [InlineData("PUT", "/api/v1/instance/metrics-access", """{"enabled":true}""")]
    [InlineData("GET", "/api/v1/instance/email-config", null)]
    [InlineData("PUT", "/api/v1/instance/email-config", """{"enabled":false}""")]
    [InlineData("POST", "/api/v1/instance/email-config/test", null)]
    [InlineData("GET", "/api/v1/instance/email-health", null)]
    [InlineData("GET", "/api/v1/instance/background-jobs", null)]
    [InlineData("GET", "/api/v1/instance/vuln-tracker-config", null)]
    [InlineData("PUT", "/api/v1/instance/vuln-tracker-config", """{"enabled":false,"baseUrl":""}""")]
    [InlineData("POST", "/api/v1/instance/vuln-tracker-config/test", null)]
    [InlineData("GET", "/api/v1/instance/vuln-tracker-health", null)]
    [InlineData("POST", "/api/v1/instance/secrets/verify", null)]
    public async Task Member_EveryInstanceRoute_IsForbidden(string method, string path, string? json)
    {
        string memberId = await _factory.CreateUser($"inst-member-{Guid.NewGuid():N}@example.com", "Password12345");
        using var member = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(memberId, "member"));
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (json is not null)
        {
            request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        }

        var resp = await member.SendAsync(request);

        await ProblemBody.AssertForbiddenAsync(resp);
    }

    [Fact]
    public async Task Admin_GetEmailHealth_ReportsTheRelayAggregateWithoutTenantIdentifiers()
    {
        using var admin = await AdminClient();

        var resp = await admin.GetAsync("/api/v1/instance/email-health");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await ProblemBody.ReadAsync(resp);
        Assert.Equal(JsonValueKind.Object, body.ValueKind);
        Assert.DoesNotContain("orgId", body.GetRawText(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("org_id", body.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Member_UpdateSettings_ChangesNothing()
    {
        using var admin = await AdminClient();
        string memberId = await _factory.CreateUser($"inst-member-{Guid.NewGuid():N}@example.com", "Password12345");
        using var member = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(memberId, "member"));
        var before = await admin.GetFromJsonAsync<JsonElement>("/api/v1/instance/settings");

        await ProblemBody.AssertForbiddenAsync(
            await member.PutAsJsonAsync("/api/v1/instance/settings", new Dictionary<string, string> { ["max_upload_bytes"] = "1" }));

        var after = await admin.GetFromJsonAsync<JsonElement>("/api/v1/instance/settings");
        Assert.Equal(before.GetRawText(), after.GetRawText());
    }

    [Fact]
    public async Task UpdateSettings_OversizedCacheWarnThreshold_IsRejected_AndNothingIsWritten()
    {
        using var admin = await AdminClient();

        var bad = await admin.PutAsJsonAsync("/api/v1/instance/settings", new Dictionary<string, string>
        {
            ["cache_size_warn_bytes"] = "-1",
        });
        var notANumber = await admin.PutAsJsonAsync("/api/v1/instance/settings", new Dictionary<string, string>
        {
            ["cache_size_warn_bytes"] = "lots",
        });

        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, notANumber.StatusCode);
        var ok = await admin.PutAsJsonAsync("/api/v1/instance/settings", new Dictionary<string, string>
        {
            ["cache_size_warn_bytes"] = "",
        });
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
    }

    [Fact]
    public async Task PutMetricsAccess_WhenEnvPinsTheKnob_Conflicts_AndTheUnpinnedKnobStillSaves()
    {
        await using var factory = new DependablyFactory
        {
            ExtraSettings = new Dictionary<string, string?> { ["METRICS_ENABLED"] = "false" },
        };
        await factory.InitializeAsync();
        using var c = factory.CreateClientWithBearer(await factory.CreateAdminJwt());

        var pinned = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new { enabled = true });
        Assert.Equal(HttpStatusCode.Conflict, pinned.StatusCode);
        Assert.Contains("METRICS_ENABLED", await pinned.Content.ReadAsStringAsync());

        var free = await c.PutAsJsonAsync("/api/v1/instance/metrics-access", new { allowedIps = new[] { "10.0.0.0/8" } });
        Assert.Equal(HttpStatusCode.OK, free.StatusCode);

        await using var allowlistPinned = new DependablyFactory
        {
            ExtraSettings = new Dictionary<string, string?> { ["METRICS_ALLOWED_IPS"] = "127.0.0.1" },
        };
        await allowlistPinned.InitializeAsync();
        using var c2 = allowlistPinned.CreateClientWithBearer(await allowlistPinned.CreateAdminJwt());
        var conflict = await c2.PutAsJsonAsync("/api/v1/instance/metrics-access", new { allowedIps = new[] { "10.0.0.0/8" } });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Contains("METRICS_ALLOWED_IPS", await conflict.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task PutEmailConfig_SecurityNoneWithCredentials_IsSavedAndFlaggedCleartext()
    {
        await using var factory = new DependablyFactory
        {
            MasterKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
        };
        await factory.InitializeAsync();
        using var c = factory.CreateClientWithBearer(await factory.CreateAdminJwt());

        var put = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 25,
            security = "none",
            username = "relay",
            password = "relay-secret",
            fromAddress = "noreply@example.com",
        });

        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.True(JsonDocument.Parse(await put.Content.ReadAsStringAsync()).RootElement
            .GetProperty("cleartextCredentials").GetBoolean());
        await using var conn = await factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'instance_email_config_updated' ORDER BY created_at DESC LIMIT 1");
        Assert.NotNull(detail);
        Assert.DoesNotContain("relay-secret", detail);
        Assert.True(JsonDocument.Parse(detail!).RootElement.GetProperty("cleartextCredentials").GetBoolean());
    }

    [Fact]
    public async Task TestEmail_SendsToTheConfiguredFromAddress_AndReportsATransportFailureAsAValidationProblem()
    {
        var sender = new CapturingMailSender();
        await using var factory = new DependablyFactory { MailSenderOverride = sender };
        await factory.InitializeAsync();
        using var c = factory.CreateClientWithBearer(await factory.CreateAdminJwt());
        var put = await c.PutAsJsonAsync("/api/v1/instance/email-config", new
        {
            enabled = true,
            host = "smtp.example.com",
            port = 25,
            security = "none",
            fromAddress = "noreply@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        int before = sender.Sent.Count;

        var ok = await c.PostAsync("/api/v1/instance/email-config/test", null);

        Assert.True(ok.StatusCode == HttpStatusCode.NoContent, await ok.Content.ReadAsStringAsync());
        var sent = Assert.Single(sender.Sent.Skip(before));
        Assert.Equal(new[] { "noreply@example.com" }, sent.Recipients);

        sender.Failure = () => new InvalidOperationException("relay refused");
        var failed = await c.PostAsync("/api/v1/instance/email-config/test", null);
        await ProblemBody.AssertValidationAsync(failed, "email");
        Assert.DoesNotContain("relay refused", await failed.Content.ReadAsStringAsync());
    }
}

/// <summary>
/// Multi-tenant mode coverage for /api/v1/instance/*. In multi mode these are
/// control-plane endpoints owned by the operator, not tenants. A tenant owner — even
/// with the <c>tenant:admin</c> capability — must receive 404, matching the project's
/// 404-on-unauthorized invariant. The system realm counterparts remain accessible to the
/// system_admin at /api/v1/system/settings and /api/v1/system/background-jobs.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceControllerMultiModeTests
    : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public InstanceControllerMultiModeTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Creates a tenant via the system surface and returns a JWT for its owner, plus the
    /// subdomain host used to reach the tenant. The owner has <c>tenant:admin</c> capability
    /// (role=owner), which would normally be sufficient for single-mode instance-settings access.
    /// </summary>
    private async Task<(string ownerJwt, string tenantHost)> CreateTenantOwnerAsync()
    {
        string slug = "im-" + Guid.NewGuid().ToString("N")[..8];
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

            // Clear the first-boot must_change_password flag so PasswordRotationGuard
            // doesn't intercept the request with 403 before the controller gate is reached.
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @ownerId",
                new { ownerId });
        }

        string jwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        string host = $"{slug}.{DependablyMultiFactory.ApexHost}";
        return (jwt, host);
    }

    // ── Multi mode: tenant owner cannot reach instance-settings endpoints ────

    [Fact]
    public async Task MultiMode_TenantOwner_GetSettings_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/settings");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_PutSettings_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "999999",
        });
        var resp = await client.PutAsync("/api/v1/instance/settings", body);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetBackgroundJobs_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/background-jobs");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetMetricsAccess_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.GetAsync("/api/v1/instance/metrics-access");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_PutMetricsAccess_Returns404()
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        var resp = await client.PutAsJsonAsync("/api/v1/instance/metrics-access", new { enabled = true });

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Theory]
    [InlineData("GET", "/api/v1/instance/email-config")]
    [InlineData("PUT", "/api/v1/instance/email-config")]
    [InlineData("POST", "/api/v1/instance/email-config/test")]
    [InlineData("GET", "/api/v1/instance/email-health")]
    [InlineData("GET", "/api/v1/instance/vuln-tracker-config")]
    [InlineData("PUT", "/api/v1/instance/vuln-tracker-config")]
    [InlineData("POST", "/api/v1/instance/vuln-tracker-config/test")]
    [InlineData("GET", "/api/v1/instance/vuln-tracker-health")]
    [InlineData("POST", "/api/v1/instance/secrets/verify")]
    public async Task MultiMode_TenantOwner_EveryRemainingInstanceRoute_Returns404(string method, string path)
    {
        var (jwt, host) = await CreateTenantOwnerAsync();
        using var client = _factory.CreateClientForHost(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method == "PUT")
        {
            request.Content = path.Contains("vuln-tracker", StringComparison.Ordinal)
                ? JsonContent.Create(new { enabled = false, baseUrl = "" })
                : JsonContent.Create(new { enabled = false });
        }

        var resp = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Multi mode: system_admin still reaches the system-realm equivalents ──

    [Fact]
    public async Task MultiMode_SystemAdmin_GetSystemSettings_Returns200()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var resp = await client.GetAsync("/api/v1/system/settings");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public async Task MultiMode_SystemAdmin_PutSystemSettings_Persists()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var body = JsonContent.Create(new Dictionary<string, string>
        {
            ["max_upload_bytes"] = "2097152",
        });
        var putResp = await client.PutAsync("/api/v1/system/settings", body);
        Assert.Equal(HttpStatusCode.NoContent, putResp.StatusCode);

        // Verify the value persisted.
        await using var conn = await _factory.Services
            .GetRequiredService<IMetadataStore>().OpenAsync();
        string? value = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes' LIMIT 1");
        Assert.Equal("2097152", value);
    }
}
