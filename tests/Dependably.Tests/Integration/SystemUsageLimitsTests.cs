using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of <c>GET</c>/<c>PATCH /api/v1/system/tenants/{slug}/usage-limits</c> in
/// multi mode: validation, the meter-to-cap map's set/clear/leave-alone semantics, the audit row,
/// reach by a system token and refusal of a tenant credential, and the synchronous recompute that
/// makes a cap change take effect on the tenant's very next protocol request — including lifting a
/// cap to restore service.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SystemUsageLimitsTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    private readonly DependablyMultiFactory _factory;
    public SystemUsageLimitsTests(DependablyMultiFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private IMetadataStore Db => _factory.Services.GetRequiredService<IMetadataStore>();

    private static string Path(string slug) => $"/api/v1/system/tenants/{slug}/usage-limits";

    private static async Task<(string OrgId, string Slug)> CreateTenantAsync(HttpClient sysClient)
    {
        string slug = "ul-" + Guid.NewGuid().ToString("N")[..8];
        var resp = await sysClient.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}-owner@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return (doc.RootElement.GetProperty("tenant").GetProperty("id").GetString()!, slug);
    }

    private static Task<HttpResponseMessage> PatchAsync(HttpClient client, string slug, string capsJson) =>
        client.PatchAsync(Path(slug), new StringContent($$"""{"caps":{{capsJson}}}""", Encoding.UTF8, "application/json"));

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage resp)
    {
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private async Task SeedEgressAsync(string orgId, long quantity)
    {
        var now = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow();
        string bucket = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUtcIso();
        await using var conn = await Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
            VALUES (@orgId, 'egress_bytes', @bucket, @quantity, 0, 1, @bucket)
            """,
            new { orgId, bucket, quantity });
    }

    private async Task<HttpResponseMessage> PublishOnTenantHostAsync(string orgId, string slug)
    {
        var (raw, _) = await _factory.Services.GetRequiredService<TokenRepository>().CreateServiceTokenAsync(
            orgId, $"pub-{Guid.NewGuid():N}"[..16], """["publish:*","read:artifact","read:metadata"]""", expiresAt: null);
        using var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        string name = $"ul-{Guid.NewGuid():N}"[..20];
        return await client.PutAsync(
            $"/npm/{name}",
            new StringContent(NpmFixtures.BuildPublishBody(name, "1.0.0"), Encoding.UTF8, "application/json"));
    }

    // ── Set, read back, clear ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Patch_sets_caps_and_get_reads_them_back_with_the_posture()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (_, slug) = await CreateTenantAsync(sys);

        using var patch = await PatchAsync(sys, slug, """{"egress_bytes":500000000000,"artifact_count":2000}""");
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);
        var body = await JsonAsync(patch);
        Assert.Equal(slug, body.GetProperty("slug").GetString());
        Assert.Equal(500_000_000_000, body.GetProperty("caps").GetProperty("egress_bytes").GetInt64());
        Assert.Equal(2000, body.GetProperty("caps").GetProperty("artifact_count").GetInt64());
        Assert.Equal("normal", body.GetProperty("usagePosture").GetString());

        using var get = await sys.GetAsync(Path(slug));
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        var read = await JsonAsync(get);
        Assert.Equal(2, read.GetProperty("caps").EnumerateObject().Count());
        Assert.Equal("normal", read.GetProperty("usagePosture").GetString());
    }

    [Fact]
    public async Task Null_clears_a_cap_and_an_omitted_meter_keeps_its_cap()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (_, slug) = await CreateTenantAsync(sys);
        (await PatchAsync(sys, slug, """{"egress_bytes":1000,"storage_bytes":2000}""")).EnsureSuccessStatusCode();

        using var patch = await PatchAsync(sys, slug, """{"egress_bytes":null}""");
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);

        var caps = (await JsonAsync(patch)).GetProperty("caps");
        Assert.False(caps.TryGetProperty("egress_bytes", out _));
        Assert.Equal(2000, caps.GetProperty("storage_bytes").GetInt64());
    }

    [Fact]
    public async Task Patch_writes_one_audit_row_with_prior_and_new_caps()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(sys);
        (await PatchAsync(sys, slug, """{"storage_bytes":2000}""")).EnsureSuccessStatusCode();

        await using var conn = await Db.OpenAsync();
        var (scope, detail) = await conn.QuerySingleAsync<(string Scope, string Detail)>(
            "SELECT scope AS Scope, detail AS Detail FROM audit_log WHERE action = 'tenant.usage_limits_changed' AND org_id = @orgId",
            new { orgId });
        Assert.Equal("system", scope);
        using var doc = JsonDocument.Parse(detail);
        Assert.Equal(slug, doc.RootElement.GetProperty("slug").GetString());
        Assert.Contains("storage_bytes", detail);
        Assert.Contains("normal", detail);
    }

    // ── Validation ───────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("""{"egress_bytes":0}""")]
    [InlineData("""{"storage_bytes":-1}""")]
    [InlineData("""{"requests":10}""")]
    // cache_storage_bytes is billed (usage_daily) but deliberately not a cap meter: proxy-cache
    // growth is bounded by storage_quota_bytes (413), never by a usage cap.
    [InlineData("""{"cache_storage_bytes":1000}""")]
    public async Task A_non_positive_cap_or_unknown_meter_is_422_and_changes_nothing(string capsJson)
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (_, slug) = await CreateTenantAsync(sys);
        (await PatchAsync(sys, slug, """{"artifact_count":5}""")).EnsureSuccessStatusCode();

        using var resp = await PatchAsync(sys, slug, capsJson.Replace("}", ""","artifact_count":null}"""));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);

        // The valid clear in the same body was not applied either.
        var caps = (await JsonAsync(await sys.GetAsync(Path(slug)))).GetProperty("caps");
        Assert.Equal(5, caps.GetProperty("artifact_count").GetInt64());
    }

    [Fact]
    public async Task A_body_without_a_caps_map_is_422()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (_, slug) = await CreateTenantAsync(sys);

        using var resp = await sys.PatchAsync(Path(slug), new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task An_unknown_slug_is_404()
    {
        using var sys = await _factory.CreateSystemAdminClient();

        using var patch = await PatchAsync(sys, "ghost-usage", """{"egress_bytes":1}""");
        using var get = await sys.GetAsync(Path("ghost-usage"));
        Assert.Equal(HttpStatusCode.NotFound, patch.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, get.StatusCode);
    }

    // ── Reach ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task A_system_token_can_set_and_read_caps_and_is_audited_as_a_service_actor()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(sys);
        var mint = await sys.PostAsJsonAsync("/api/v1/system/tokens", new
        {
            name = "usage-caps-" + Guid.NewGuid().ToString("N")[..6],
            // now-ok: expiresAt is validated against the host's real clock (TimeProvider.System here).
            expiresAt = DateTimeOffset.UtcNow.AddDays(30),
        });
        mint.EnsureSuccessStatusCode();
        string token = (await JsonAsync(mint)).GetProperty("token").GetString()!;

        using var tokenClient = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        tokenClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var patch = await PatchAsync(tokenClient, slug, """{"egress_metadata_bytes":42}""");
        Assert.Equal(HttpStatusCode.OK, patch.StatusCode);
        using var get = await tokenClient.GetAsync(Path(slug));
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);

        await using var conn = await Db.OpenAsync();
        string actorKind = await conn.QuerySingleAsync<string>(
            "SELECT actor_kind FROM audit_log WHERE action = 'tenant.usage_limits_changed' AND org_id = @orgId",
            new { orgId });
        Assert.Equal(ActorKinds.Service, actorKind);
    }

    [Fact]
    public async Task A_tenant_credential_cannot_reach_usage_limits()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(sys);
        string ownerId;
        await using (var conn = await Db.OpenAsync())
        {
            ownerId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM users WHERE tenant_id = @orgId LIMIT 1", new { orgId })
                ?? throw new InvalidOperationException("owner missing");
        }

        string ownerJwt = await _factory.CreateTenantJwt(ownerId, orgId, role: "owner");
        foreach (string host in new[] { DependablyMultiFactory.ApexHost, $"{slug}.{DependablyMultiFactory.ApexHost}" })
        {
            using var client = _factory.CreateClientForHost(host);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ownerJwt);

            using var patch = await PatchAsync(client, slug, """{"egress_bytes":null}""");
            using var get = await client.GetAsync(Path(slug));
            Assert.True(patch.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized, $"{host}: got {(int)patch.StatusCode}");
            Assert.True(get.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized, $"{host}: got {(int)get.StatusCode}");
        }

        using var anonymous = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        using var anonPatch = await PatchAsync(anonymous, slug, """{"egress_bytes":1}""");
        Assert.True(anonPatch.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Unauthorized);

        var caps = await _factory.Services.GetRequiredService<UsagePostureRepository>().GetCapsAsync(orgId);
        Assert.Empty(caps);
    }

    // ── The PATCH takes effect on the next request, and lifting a cap restores service ───────

    [Fact]
    public async Task Setting_a_cap_over_current_usage_refuses_the_next_upload_and_lifting_it_restores_it()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (orgId, slug) = await CreateTenantAsync(sys);
        await SeedEgressAsync(orgId, 2000);

        // Warm the tenant resolver's cache with the normal posture first, so the refusal below
        // proves the PATCH evicted it rather than an empty cache happening to read the new row.
        using (var before = await PublishOnTenantHostAsync(orgId, slug))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        using (var capped = await PatchAsync(sys, slug, """{"egress_bytes":1000}"""))
        {
            Assert.Equal(HttpStatusCode.OK, capped.StatusCode);
            Assert.Equal("downloads_throttled", (await JsonAsync(capped)).GetProperty("usagePosture").GetString());
        }

        using (var refused = await PublishOnTenantHostAsync(orgId, slug))
        {
            Assert.Equal(HttpStatusCode.PaymentRequired, refused.StatusCode);
            Assert.Equal("UsageCapReached", (await JsonAsync(refused)).GetProperty("reason").GetString());
        }

        // Raise the cap above usage: normal again, on the next request.
        using (var raised = await PatchAsync(sys, slug, """{"egress_bytes":2001}"""))
        {
            Assert.Equal("normal", (await JsonAsync(raised)).GetProperty("usagePosture").GetString());
        }

        using (var restored = await PublishOnTenantHostAsync(orgId, slug))
        {
            Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        }

        // Cap it again, then clear it outright: a pilot again, and never enforced.
        (await PatchAsync(sys, slug, """{"egress_bytes":1000}""")).EnsureSuccessStatusCode();
        using (var cleared = await PatchAsync(sys, slug, """{"egress_bytes":null}"""))
        {
            var body = await JsonAsync(cleared);
            Assert.Equal("normal", body.GetProperty("usagePosture").GetString());
            Assert.Empty(body.GetProperty("caps").EnumerateObject());
        }

        using var afterClear = await PublishOnTenantHostAsync(orgId, slug);
        Assert.Equal(HttpStatusCode.OK, afterClear.StatusCode);
    }

    [Fact]
    public async Task A_cap_on_one_tenant_leaves_another_tenant_alone()
    {
        using var sys = await _factory.CreateSystemAdminClient();
        var (cappedId, cappedSlug) = await CreateTenantAsync(sys);
        var (otherId, otherSlug) = await CreateTenantAsync(sys);
        await SeedEgressAsync(cappedId, 5000);
        await SeedEgressAsync(otherId, 5000);

        (await PatchAsync(sys, cappedSlug, """{"egress_bytes":1000}""")).EnsureSuccessStatusCode();

        using var capped = await PublishOnTenantHostAsync(cappedId, cappedSlug);
        using var other = await PublishOnTenantHostAsync(otherId, otherSlug);
        Assert.Equal(HttpStatusCode.PaymentRequired, capped.StatusCode);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }
}
