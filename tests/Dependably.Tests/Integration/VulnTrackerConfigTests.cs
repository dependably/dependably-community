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
/// Single-tenant mode coverage for <c>/api/v1/instance/vuln-tracker-config</c>. The connection to
/// the external vulnerability tracker is instance-level state — one per deployment, serving every
/// tenant — so these tests pin the same posture the instance SMTP transport establishes:
/// write-only credential, a refusal to store it without a master key, and shared validation with
/// the apex surface covered in the multi-mode class below.
/// </summary>
[Trait("Category", "Integration")]
public sealed class InstanceVulnTrackerConfigEndpointTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Route = "/api/v1/instance/vuln-tracker-config";

    private readonly DependablyFactory _factory;
    public InstanceVulnTrackerConfigEndpointTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<HttpClient> AdminClient(DependablyFactory factory)
    {
        // CreateClient() triggers WebApplicationFactory host startup (schema init + first boot);
        // it must run before CreateAdminJwt() reads the seeded default org/owner.
        var client = factory.CreateClient();
        string jwt = await factory.CreateAdminJwt();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static string NewMasterKey() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static async Task<JsonElement> ReadJson(HttpResponseMessage resp) =>
        JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

    [Fact]
    public async Task Member_Get_Returns403()
    {
        string memberId = await _factory.CreateUser($"vtc-mem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync(Route);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_Get_Succeeds()
    {
        // Adversarial twin of the member 403: proves the capability gate is what rejects a member,
        // not the route being unreachable for everyone.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.GetAsync(Route);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Get_AbsentRows_ReturnsDocumentedDefaults()
    {
        // Own factory: the shared fixture's instance_settings may already carry vuln_tracker_*
        // rows written by another test in this class (xUnit does not guarantee method order).
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var root = await ReadJson(await c.GetAsync(Route));

        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.Null(root.GetProperty("baseUrl").GetString());
        Assert.False(root.GetProperty("hasToken").GetBoolean());
        Assert.Equal(168, root.GetProperty("maxStalenessHours").GetInt32());
        Assert.Equal(100, root.GetProperty("batchSize").GetInt32());
        Assert.False(root.GetProperty("configured").GetBoolean());
        Assert.False(root.GetProperty("active").GetBoolean());
        Assert.False(root.GetProperty("secretsAvailable").GetBoolean());
    }

    [Fact]
    public async Task Put_TokenWithoutMasterKey_Returns422_AndWritesNothing()
    {
        // The shared factory runs with no DEPENDABLY_MASTER_KEY. The refusal is the point: the
        // write path would otherwise persist a live bearer credential in plaintext.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_super_secret",
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        // Nothing may have landed — not even the valid non-secret fields.
        var root = await ReadJson(await c.GetAsync(Route));
        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.Null(root.GetProperty("baseUrl").GetString());
        Assert.False(root.GetProperty("hasToken").GetBoolean());
    }

    [Fact]
    public async Task Put_WithoutMasterKey_AndWithoutToken_Succeeds()
    {
        // Twin of the refusal above: an unencrypted deployment can still configure the
        // connection, it just cannot store a credential. Without this, a passing refusal test
        // would be equally consistent with the endpoint being broken for everyone.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = await ReadJson(resp);
        Assert.True(root.GetProperty("configured").GetBoolean());
        Assert.False(root.GetProperty("hasToken").GetBoolean());
    }

    [Theory]
    [InlineData("not-a-url", 168, 100)]
    [InlineData("file:///etc/passwd", 168, 100)]
    [InlineData("https://tracker.example.com", 0, 100)]
    [InlineData("https://tracker.example.com", 168, 1001)]
    public async Task Put_InvalidField_Returns422_AndWritesNothing(string baseUrl, int staleness, int batch)
    {
        // Mixed-validity requests: the other fields are all fine in each case. Validation must
        // reject the whole PUT before any instance_settings row is touched, or a rejected save
        // would still half-apply.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl,
            token = (string?)null,
            maxStalenessHours = staleness,
            batchSize = batch,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        var root = await ReadJson(await c.GetAsync(Route));
        Assert.False(root.GetProperty("enabled").GetBoolean());
        Assert.Null(root.GetProperty("baseUrl").GetString());
    }

    [Fact]
    public async Task Put_LoopbackHost_IsAccepted_BecauseASidecarIsTheNormalDeployment()
    {
        // This test previously asserted the OPPOSITE, and that was the bug: a self-hosted tracker
        // on loopback is the shape this feature is designed for, and refusing it made the feature
        // unusable with no configuration that lifted it — WEBHOOK_ALLOW_PRIVATE reached only the
        // save-time check, and loopback is blocked even by the relaxed predicate.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "http://127.0.0.1:8090/",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Put_InstanceMetadataHost_Returns422()
    {
        // The twin, and the one range that stays refused: a request forged through this path to
        // the cloud metadata endpoint would be a real credential escalation, and no legitimate
        // tracker lives there.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "http://169.254.169.254/latest/meta-data/",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Put_HostnameThatIsNotAnIpLiteral_IsAccepted()
    {
        // Twin of the blocked-literal test, and it pins a deliberate limit rather than an
        // oversight: a hostname is not resolved at save time, because DNS can change between
        // save and request. The authoritative gate is the connect-time guard.
        await using var factory = new DependablyFactory();
        using var c = await AdminClient(factory);

        var resp = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.internal.example.com",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Put_RoundTrip_TokenNeverEchoed_AndStoredEncrypted()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        var put = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_super_secret",
            maxStalenessHours = 72,
            batchSize = 250,
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        string putBody = await put.Content.ReadAsStringAsync();
        Assert.DoesNotContain("osvst_super_secret", putBody);
        var putRoot = JsonDocument.Parse(putBody).RootElement;
        Assert.True(putRoot.GetProperty("hasToken").GetBoolean());
        Assert.True(putRoot.GetProperty("active").GetBoolean());
        Assert.False(putRoot.TryGetProperty("token", out _));

        string getBody = await (await c.GetAsync(Route)).Content.ReadAsStringAsync();
        Assert.DoesNotContain("osvst_super_secret", getBody);
        var getRoot = JsonDocument.Parse(getBody).RootElement;
        Assert.Equal("https://tracker.example.com", getRoot.GetProperty("baseUrl").GetString());
        Assert.Equal(72, getRoot.GetProperty("maxStalenessHours").GetInt32());
        Assert.Equal(250, getRoot.GetProperty("batchSize").GetInt32());
        Assert.True(getRoot.GetProperty("hasToken").GetBoolean());

        // The stored value is envelope-encrypted at rest, not merely hidden from the response.
        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? raw = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'vuln_tracker_token' LIMIT 1");
        Assert.NotNull(raw);
        Assert.StartsWith("enc:v1:", raw);
        Assert.DoesNotContain("osvst_super_secret", raw);
    }

    [Fact]
    public async Task Put_EmptyToken_PreservesStoredCredential()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_original",
            maxStalenessHours = 168,
            batchSize = 100,
        });

        // Second PUT with an empty token and a changed horizon: the horizon change must land and
        // the credential must survive.
        var second = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "",
            maxStalenessHours = 24,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        var root = await ReadJson(second);
        Assert.True(root.GetProperty("hasToken").GetBoolean());
        Assert.Equal(24, root.GetProperty("maxStalenessHours").GetInt32());
    }

    [Fact]
    public async Task Put_ClearingTheBaseUrl_AlsoClearsTheStoredCredential()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_original",
            maxStalenessHours = 168,
            batchSize = 100,
        });

        var cleared = await c.PutAsJsonAsync(Route, new
        {
            enabled = false,
            baseUrl = "",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);

        var root = await ReadJson(cleared);
        Assert.False(root.GetProperty("hasToken").GetBoolean());
        Assert.False(root.GetProperty("configured").GetBoolean());

        // Read back through the repository, which decrypts: "cleared" is a property of the value
        // a reader sees, not of the row's presence. The row itself survives as ciphertext of an
        // empty string, because the write path envelope-protects every value for a secret key
        // — so the raw column is asserted separately, on the only thing that matters about it.
        var orgs = factory.Services.GetRequiredService<OrgRepository>();
        string? decrypted = await orgs.GetInstanceSettingAsync("vuln_tracker_token");
        Assert.True(string.IsNullOrEmpty(decrypted), $"token survived a teardown: '{decrypted}'");

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? raw = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'vuln_tracker_token' LIMIT 1");
        Assert.DoesNotContain("osvst_original", raw ?? "");
    }

    [Fact]
    public async Task Put_DisablingWithoutClearingTheBaseUrl_KeepsTheCredential()
    {
        // The twin that makes the teardown test meaningful: pausing enrichment must not discard
        // the credential, or an operator would have to choose between pausing and re-provisioning.
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_original",
            maxStalenessHours = 168,
            batchSize = 100,
        });

        var paused = await c.PutAsJsonAsync(Route, new
        {
            enabled = false,
            baseUrl = "https://tracker.example.com",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, paused.StatusCode);

        var root = await ReadJson(paused);
        Assert.True(root.GetProperty("hasToken").GetBoolean());
        Assert.True(root.GetProperty("configured").GetBoolean());
        Assert.False(root.GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Put_AuditsTheResultingState_WithoutTheCredential()
    {
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey() };
        using var c = await AdminClient(factory);

        await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = "osvst_super_secret",
            maxStalenessHours = 168,
            batchSize = 100,
        });

        var store = factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'instance_vuln_tracker_config_updated' "
            + "ORDER BY rowid DESC LIMIT 1");

        Assert.NotNull(detail);
        Assert.DoesNotContain("osvst_super_secret", detail);
        Assert.Contains("tracker.example.com", detail);

        var root = JsonDocument.Parse(detail!).RootElement;
        Assert.True(root.GetProperty("tokenRotated").GetBoolean());
        Assert.True(root.GetProperty("hasToken").GetBoolean());
    }

    // ── Health route ─────────────────────────────────────────────────────────

    private const string HealthRoute = "/api/v1/instance/vuln-tracker-health";

    [Fact]
    public async Task Member_GetHealth_Returns403()
    {
        string memberId = await _factory.CreateUser($"vth-mem-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(memberId, "member");
        using var c = _factory.CreateClientWithBearer(jwt);

        var resp = await c.GetAsync(HealthRoute);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Admin_GetHealth_WithNoConnectionConfigured_ReportsNotConfigured()
    {
        // Adversarial twin of the member 403 above, and the state most deployments are
        // permanently in: no base URL means no connection exists, which the health route must
        // report distinctly from a configured-but-idle one.
        using var c = await AdminClient(_factory);

        var resp = await c.GetAsync(HealthRoute);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = await ReadJson(resp);
        Assert.False(root.GetProperty("configured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("health").ValueKind);
    }

    [Fact]
    public async Task Admin_GetHealth_AfterConfiguring_ReportsConfiguredWithNoAttemptYet()
    {
        // Saving a connection makes it configured immediately, before any scan pass has ever run
        // against it — the "configured but never attempted" state the aggregator keeps apart from
        // both "not configured" and "failing".
        using var c = await AdminClient(_factory);
        var put = await c.PutAsJsonAsync(Route, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            maxStalenessHours = 24,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var resp = await c.GetAsync(HealthRoute);
        var root = await ReadJson(resp);

        Assert.True(root.GetProperty("configured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("health").ValueKind);
        Assert.Equal(0, root.GetProperty("recentFetches").GetArrayLength());

        // Clean up so a later test in this shared-factory class sees "not configured" again.
        await c.PutAsJsonAsync(Route, new { enabled = false, baseUrl = "" });
    }
}

/// <summary>
/// Multi-tenant mode: the tracker connection is a control-plane concern owned by the operator, so
/// a tenant owner — even one holding <c>tenant:admin</c> — must receive 404 on the instance route
/// and must not reach the apex system route. The system realm is where the one connection lives.
/// </summary>
[Trait("Category", "Integration")]
public sealed class VulnTrackerConfigMultiModeTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private const string InstanceRoute = "/api/v1/instance/vuln-tracker-config";
    private const string SystemRoute = "/api/v1/system/vuln-tracker-config";

    private readonly DependablyMultiFactory _factory;
    public VulnTrackerConfigMultiModeTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> TenantOwnerClientAsync()
    {
        string slug = "vtc-" + Guid.NewGuid().ToString("N")[..8];
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

            // Clear the first-boot must_change_password flag so PasswordRotationGuard doesn't
            // intercept with 403 before the controller gate is reached.
            await conn.ExecuteAsync(
                "UPDATE users SET must_change_password = 0 WHERE id = @ownerId", new { ownerId });
        }

        string jwt = await _factory.CreateTenantJwt(userId: ownerId, tenantId: tenantId, role: "owner");
        var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    [Fact]
    public async Task MultiMode_TenantOwner_GetInstanceRoute_Returns404()
    {
        using var client = await TenantOwnerClientAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(InstanceRoute)).StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_PutInstanceRoute_Returns404()
    {
        using var client = await TenantOwnerClientAsync();
        var resp = await client.PutAsJsonAsync(InstanceRoute, new { enabled = true });
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_CannotReachTheApexSurface()
    {
        // The tenant-facing 404 above only matters if the apex route is not simply an alternate
        // door into the same setting for the same principal.
        using var client = await TenantOwnerClientAsync();
        var resp = await client.GetAsync(SystemRoute);
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task MultiMode_TenantOwner_CannotReachTheApexTestRoute()
    {
        // The probe triggers an outbound request from the deployment. If a tenant could fire it,
        // one tenant would be able to make the operator's shared connection burn the deployment's
        // producer quota, and to time a host of the operator's choosing.
        using var client = await TenantOwnerClientAsync();
        var resp = await client.PostAsync(SystemRoute + "/test", content: null);

        // Asserted as a specific rejection rather than "not 200". A 422 here would ALSO satisfy
        // NotEqual(OK) while meaning the opposite of what this test claims: that the tenant
        // reached the handler and was merely told nothing is configured.
        Assert.Contains(resp.StatusCode, new[]
        {
            HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.NotFound,
        });
    }

    [Fact]
    public async Task MultiMode_TenantOwner_TestOnTheInstanceRoute_Returns404()
    {
        using var client = await TenantOwnerClientAsync();
        var resp = await client.PostAsync(InstanceRoute + "/test", content: null);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task SystemAdmin_TestWithNoConnectionConfigured_Is422NotAFailedProbe()
    {
        // Adversarial twin of the two refusals above: the apex principal DOES reach the route.
        // What it gets back is the distinction this endpoint exists to preserve — nothing is
        // configured, so the operation could not run, which is not the same answer as a tracker
        // that was dialled and did not respond.
        using var client = await _factory.CreateSystemAdminClient();

        // Clear any connection a sibling test in this class left behind.
        var clear = await client.PutAsJsonAsync(SystemRoute, new { enabled = false, baseUrl = "" });
        Assert.Equal(HttpStatusCode.OK, clear.StatusCode);

        var resp = await client.PostAsync(SystemRoute + "/test", content: null);
        Assert.Equal(HttpStatusCode.UnprocessableContent, resp.StatusCode);

        // And nothing was recorded: an integration that does not exist has no failure to log.
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM vuln_tracker_fetch_log WHERE kind = 'probe'"));
    }

    // ── Health route ─────────────────────────────────────────────────────────

    private const string SystemHealthRoute = "/api/v1/system/vuln-tracker-health";
    private const string InstanceHealthRoute = "/api/v1/instance/vuln-tracker-health";

    [Fact]
    public async Task MultiMode_TenantOwner_HealthRoutes_AreUnreachable()
    {
        // Same posture as the config surface: connection health is control-plane data about the
        // operator's own connection, not a tenant's business, so a tenant gets 404 on the instance
        // door and cannot reach the apex one.
        using var client = await TenantOwnerClientAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync(InstanceHealthRoute)).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync(SystemHealthRoute)).StatusCode);
    }

    [Fact]
    public async Task SystemAdmin_GetHealth_ReflectsWhatTheConfigSurfaceJustSaved()
    {
        // The apex config route and the apex health route read the same instance-level
        // connection; this pins that they agree rather than each holding a stale view.
        using var client = await _factory.CreateSystemAdminClient();

        var put = await client.PutAsJsonAsync(SystemRoute, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            maxStalenessHours = 12,
            batchSize = 50,
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var resp = await client.GetAsync(SystemHealthRoute);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("configured").GetBoolean());
        Assert.True(root.GetProperty("enabled").GetBoolean());
        Assert.Equal(12, root.GetProperty("maxStalenessHours").GetInt32());

        await client.PutAsJsonAsync(SystemRoute, new { enabled = false, baseUrl = "" });
    }

    [Fact]
    public async Task SystemAdmin_Get_ReturnsTheConnectionWithoutTheCredential()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.GetAsync(SystemRoute);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(root.GetProperty("enabled").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.True(root.GetProperty("hasToken").ValueKind is JsonValueKind.True or JsonValueKind.False);
        Assert.False(root.TryGetProperty("token", out _));
    }

    [Fact]
    public async Task SystemAdmin_Put_RoundTripsThroughTheApexSurface()
    {
        using var client = await _factory.CreateSystemAdminClient();

        var put = await client.PutAsJsonAsync(SystemRoute, new
        {
            enabled = true,
            baseUrl = "https://tracker.example.com",
            token = (string?)null,
            maxStalenessHours = 96,
            batchSize = 200,
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var root = JsonDocument.Parse(await (await client.GetAsync(SystemRoute)).Content.ReadAsStringAsync())
            .RootElement;
        Assert.Equal("https://tracker.example.com", root.GetProperty("baseUrl").GetString());
        Assert.Equal(96, root.GetProperty("maxStalenessHours").GetInt32());
        Assert.Equal(200, root.GetProperty("batchSize").GetInt32());
    }

    [Fact]
    public async Task SystemAdmin_Put_InvalidBaseUrl_Returns422()
    {
        using var client = await _factory.CreateSystemAdminClient();
        var resp = await client.PutAsJsonAsync(SystemRoute, new
        {
            enabled = true,
            baseUrl = "not-a-url",
            token = (string?)null,
            maxStalenessHours = 168,
            batchSize = 100,
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }
}
