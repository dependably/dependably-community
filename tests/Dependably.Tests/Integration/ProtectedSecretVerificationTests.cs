using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Dependably.Tests.Integration;

/// <summary>
/// Stored-secret verification end to end: the apex <c>POST /api/v1/system/secrets/verify</c>, its
/// single-mode <c>/api/v1/instance/</c> counterpart, and the boot-time run, against a live host
/// with a master key. Runs in the <c>integration-tests-postgres-rls</c> job too, where the sweep
/// has to read every org's rows through enforced row-level security from outside any request.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProtectedSecretVerificationTests
{
    private const string SystemRoute = "/api/v1/system/secrets/verify";
    private const string InstanceRoute = "/api/v1/instance/secrets/verify";

    private static readonly TimeSpan Completion = TimeSpan.FromSeconds(60);

    private static string NewMasterKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private sealed record Seeded(string OrgId, string WebhookGood, string WebhookBad, string UpstreamBad, string UserBad, IReadOnlyList<string> Sensitive);

    // Seeds one org's worth of good and corrupted secrets through an owner connection, the way a
    // pre-fix release could have left them. Returns the identities and every sensitive string.
    private static async Task<Seeded> SeedAsync(IServiceProvider services, string masterKey, string orgId)
    {
        var sensitive = new List<string>();
        using var envelope = TestEnvelope.Configured(Convert.FromBase64String(masterKey));
        string Good(string plaintext)
        {
            string stored = envelope.Protect(plaintext);
            sensitive.Add(plaintext);
            sensitive.Add(stored[EnvelopeProtector.EncryptedPrefix.Length..]);
            return stored;
        }

        string Bad(string plaintext)
        {
            string stored = CorruptCiphertext.Envelope(envelope, plaintext);
            sensitive.Add(plaintext);
            sensitive.Add(stored[EnvelopeProtector.EncryptedPrefix.Length..]);
            return stored;
        }

        string suffix = Guid.NewGuid().ToString("N")[..8];
        var seeded = new Seeded(orgId, "whg-" + suffix, "whb-" + suffix, "upb-" + suffix, "usb-" + suffix, sensitive);

        await using var conn = await services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("test seeding across orgs");

        string mfaStored = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'mfa_encryption_key'")
            ?? throw new InvalidOperationException("mfa_encryption_key missing; did first boot run?");
        using var totp = new MfaSecretProtector(Convert.FromBase64String(envelope.Unprotect(mfaStored)));
        string badTotp = CorruptCiphertext.Totp(totp, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        sensitive.Add(badTotp);

        await conn.ExecuteAsync(
            "INSERT INTO webhook_subscription (id, org_id, url, secret) VALUES (@id, @orgId, 'https://hooks.example.com/a', @secret)",
            new { id = seeded.WebhookGood, orgId, secret = Good("webhook-hmac-good-" + suffix) });
        await conn.ExecuteAsync(
            "INSERT INTO webhook_subscription (id, org_id, url, secret) VALUES (@id, @orgId, 'https://hooks.example.com/b', @secret)",
            new { id = seeded.WebhookBad, orgId, secret = Bad("webhook-hmac-bad-" + suffix) });
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, auth_type, secret)
            VALUES (@id, @orgId, 'npm', @url, 'bearer', @secret)
            """,
            new { id = seeded.UpstreamBad, orgId, url = "https://registry.example.com/" + suffix, secret = Bad("upstream-token-" + suffix) });
        await conn.ExecuteAsync(
            """
            INSERT INTO alert_settings (org_id, slack_enabled, slack_webhook_url) VALUES (@orgId, 1, @url)
            ON CONFLICT (org_id) DO UPDATE SET slack_enabled = 1, slack_webhook_url = excluded.slack_webhook_url
            """,
            new { orgId, url = Bad("https://hooks.slack.com/services/T0/B0/" + suffix) });
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, mfa_authenticator_key)
            VALUES (@id, @orgId, @email, 'x', @totp)
            """,
            new { id = seeded.UserBad, orgId, email = seeded.UserBad + "@example.com", totp = badTotp });

        return seeded;
    }

    private static async Task<string> CreateTenantAsync(DependablyMultiFactory factory)
    {
        using var sysClient = await factory.CreateSystemAdminClient();
        var resp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug = "sv-" + Guid.NewGuid().ToString("N")[..8],
            ownerEmail = $"o-{Guid.NewGuid():N}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!;
    }

    private static async Task<int> AuditCountAsync(IServiceProvider services, string action)
    {
        await using var conn = await services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("test reads instance-scoped audit rows");
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = @action AND scope = 'system'", new { action });
    }

    private static HashSet<(string Kind, string Table, string RowId, string? OrgId, string Reason)> Failures(JsonElement root) =>
        root.GetProperty("failures").EnumerateArray()
            .Select(f => (
                f.GetProperty("kind").GetString()!,
                f.GetProperty("table").GetString()!,
                f.GetProperty("rowId").GetString()!,
                f.GetProperty("orgId").ValueKind == JsonValueKind.Null ? null : f.GetProperty("orgId").GetString(),
                f.GetProperty("reason").GetString()!))
            .ToHashSet();

    [Fact]
    public async Task System_ReportsEveryCorruptedRowByIdentity_NeverByValue_AndAudits()
    {
        string masterKey = NewMasterKey();
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await factory.InitializeAsync();
        string orgId = await CreateTenantAsync(factory);
        var seeded = await SeedAsync(factory.Services, masterKey, orgId);

        using var client = await factory.CreateSystemAdminClient();
        var resp = await client.PostAsync(SystemRoute, null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        const string Auth = ProtectedSecretFailureReasons.AuthenticationFailed;
        var failures = Failures(root);
        Assert.Contains((ProtectedSecretKinds.WebhookSecret, "webhook_subscription", seeded.WebhookBad, orgId, Auth), failures);
        Assert.Contains((ProtectedSecretKinds.UpstreamCredential, "upstream_registry", seeded.UpstreamBad, orgId, Auth), failures);
        Assert.Contains((ProtectedSecretKinds.AlertSlackWebhookUrl, "alert_settings", orgId, orgId, Auth), failures);
        Assert.Contains((ProtectedSecretKinds.UserTotpKey, "users", seeded.UserBad, orgId, Auth), failures);
        Assert.DoesNotContain(failures, f => f.RowId == seeded.WebhookGood);
        Assert.True(root.GetProperty("masterKeyConfigured").GetBoolean());
        Assert.True(root.GetProperty("failed").GetInt32() >= 4);
        // The instance secrets first boot wrote under the master key all decrypt.
        Assert.DoesNotContain(failures, f => f.Table == "instance_settings");

        foreach (string value in seeded.Sensitive)
        {
            Assert.DoesNotContain(value, body, StringComparison.Ordinal);
        }

        Assert.Equal(1, await AuditCountAsync(factory.Services, "system_admin.protected_secrets_verified"));
    }

    [Fact]
    public async Task System_RefusesAnonymousAndTenantSessions()
    {
        await using var factory = new DependablyMultiFactory { MasterKey = NewMasterKey() };
        await factory.InitializeAsync();
        string orgId = await CreateTenantAsync(factory);

        using var anonymous = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync(SystemRoute, null)).StatusCode);

        string ownerId;
        await using (var conn = await factory.Services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("test looks up the tenant owner"))
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId LIMIT 1", new { orgId })
                ?? throw new InvalidOperationException("owner user missing");
        }

        // A tenant owner's session is refused by route scoping, which answers 404 rather than 403
        // so the system realm is not discoverable from a tenant.
        using var tenant = factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        tenant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", await factory.CreateTenantJwt(ownerId, orgId));
        Assert.Equal(HttpStatusCode.NotFound, (await tenant.PostAsync(SystemRoute, null)).StatusCode);

        Assert.Equal(0, await AuditCountAsync(factory.Services, "system_admin.protected_secrets_verified"));
    }

    [Fact]
    public async Task Verifier_ReadsEveryOrgFromOutsideARequest()
    {
        // The boot-time run has no request and no declared tenant. Under enforced row-level
        // security a sweep that relied on its caller's scope would raise or see nothing.
        string masterKey = NewMasterKey();
        await using var factory = new DependablyMultiFactory { MasterKey = masterKey };
        await factory.InitializeAsync();
        var first = await SeedAsync(factory.Services, masterKey, await CreateTenantAsync(factory));
        var second = await SeedAsync(factory.Services, masterKey, await CreateTenantAsync(factory));

        var verifier = factory.Services.GetRequiredService<ProtectedSecretVerifier>();
        var report = await TestHarnessDbScope.AsHostAsync(() => verifier.VerifyAsync());

        Assert.Contains(report.Failures, f => f.RowId == first.WebhookBad && f.OrgId == first.OrgId);
        Assert.Contains(report.Failures, f => f.RowId == second.WebhookBad && f.OrgId == second.OrgId);
        Assert.DoesNotContain(report.Failures, f => f.RowId == first.WebhookGood || f.RowId == second.WebhookGood);
    }

    [Fact]
    public async Task Instance_SingleMode_RequiresTenantConfigure_AndAudits()
    {
        string masterKey = NewMasterKey();
        await using var factory = new DependablyFactory { MasterKey = masterKey };
        await factory.InitializeAsync();

        using var admin = factory.CreateClientWithBearer(await factory.CreateAdminJwt());
        var resp = await admin.PostAsync(InstanceRoute, null);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using (var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("checked").GetInt32() > 0);
            Assert.Equal(0, doc.RootElement.GetProperty("failed").GetInt32());
        }

        Assert.Equal(1, await AuditCountAsync(factory.Services, "instance_protected_secrets_verified"));

        string memberId = await factory.CreateUser($"m-{Guid.NewGuid():N}@example.com", "MemberPassword123!");
        using var member = factory.CreateClientWithBearer(await factory.CreateUserJwt(memberId, "member"));
        Assert.Equal(HttpStatusCode.Forbidden, (await member.PostAsync(InstanceRoute, null)).StatusCode);

        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync(InstanceRoute, null)).StatusCode);

        Assert.Equal(1, await AuditCountAsync(factory.Services, "instance_protected_secrets_verified"));
    }

    [Fact]
    public async Task System_IsRateLimitedPerCaller()
    {
        await using var factory = new DependablyMultiFactory { MasterKey = NewMasterKey() };
        await factory.InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        var statuses = new List<HttpStatusCode>();
        for (int i = 0; i < 8; i++)
        {
            statuses.Add((await client.PostAsync(SystemRoute, null)).StatusCode);
        }

        // Six a minute per caller: the first six run, the rest are refused before sweeping.
        Assert.Equal(Enumerable.Repeat(HttpStatusCode.OK, 6), statuses.Take(6));
        Assert.All(statuses.Skip(6), s => Assert.Equal(HttpStatusCode.TooManyRequests, s));
        Assert.Equal(6, await AuditCountAsync(factory.Services, "system_admin.protected_secrets_verified"));
    }

    [Fact]
    public async Task Instance_IsNotServedInMultiMode()
    {
        await using var factory = new DependablyMultiFactory { MasterKey = NewMasterKey() };
        await factory.InitializeAsync();
        using var client = await factory.CreateSystemAdminClient();

        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync(InstanceRoute, null)).StatusCode);
    }

    [Fact]
    public async Task BootCheck_RunsAfterTheHostStarts_AndLogsItsSummary()
    {
        var sink = new CapturingLogSink();
        await using var factory = new DependablyFactory { MasterKey = NewMasterKey(), LogSink = sink };
        await factory.InitializeAsync();

        // The host answered requests before this point, so startup did not wait on the sweep.
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);

        var check = factory.Services.GetServices<IHostedService>().OfType<ProtectedSecretBootCheck>().Single();
        await check.ExecuteTask!.WaitAsync(Completion);

        Assert.True(sink.Contains("Stored secret check:"), "the boot check logged no summary");
        Assert.False(sink.Contains("cannot be decrypted", Serilog.Events.LogEventLevel.Warning));
    }
}
