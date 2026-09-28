using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End to end, the tenant rate-limit budget is charged only for traffic the org serves as its
/// own. An org that refuses anonymous pull is never 429'd by a burst of anonymous or other-org
/// requests, and its own clients are served straight after; the same burst against an org that
/// allows anonymous pull is its own egress and still meets the budget. Both postures are pinned,
/// the ordinary budget (<c>TENANT_RATE_LIMIT_PERMITS</c>) and <c>downloads_throttled</c>
/// (<c>TENANT_THROTTLED_RATE_LIMIT_PERMITS</c>), each with its charged twin.
/// </summary>
[Trait("Category", "Integration")]
public sealed class TenantBudgetAttributionTests
{
    private const int Burst = 20;

    private static DependablyFactory BudgetFactory() => new()
    {
        ExtraSettings = new Dictionary<string, string?>
        {
            ["TENANT_RATE_LIMIT_PERMITS"] = "2",
            ["TENANT_RATE_LIMIT_QUEUE"] = "0",
        },
    };

    private static DependablyFactory ThrottledFactory() => new()
    {
        ExtraSettings = new Dictionary<string, string?>
        {
            ["TENANT_THROTTLED_RATE_LIMIT_PERMITS"] = "2",
            ["TENANT_THROTTLED_RATE_LIMIT_QUEUE"] = "0",
        },
    };

    private sealed class Scenario(DependablyFactory factory) : IAsyncDisposable
    {
        public DependablyFactory Factory { get; } = factory;

        public string Package { get; } = "attrib-" + Guid.NewGuid().ToString("N")[..10];

        public string OrgId { get; private set; } = "";

        private IMetadataStore Db => Factory.Services.GetRequiredService<IMetadataStore>();

        public async Task StartAsync(bool anonymousPull, bool throttled)
        {
            await Factory.InitializeAsync();
            await using (var conn = await Db.OpenAsync())
            {
                OrgId = await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'")
                    ?? throw new InvalidOperationException("default org missing");
            }

            await Factory.PushNpmPackage(Package, "1.0.0");
            await SetAnonymousPullAsync(anonymousPull);
            if (throttled)
            {
                await ThrottleAsync();
            }

            // The publish above drew on the same window this scenario measures, and a permit stays
            // held until the segment it was drawn in leaves the window: up to one window plus one
            // segment. Wait that long, with margin for the replenishment timer.
            var drain = TenantRateLimiter.Window
                + (TenantRateLimiter.Window / TenantRateLimiter.WindowSegments)
                + TimeSpan.FromMilliseconds(250);

            // now-ok: the sliding window replenishes on its own real-time timer, which a fake
            // clock cannot advance.
            await Task.Delay(drain, TimeProvider.System, CancellationToken.None);
        }

        private async Task SetAnonymousPullAsync(bool on)
        {
            await using (var conn = await Db.OpenAsync())
            {
                int rows = await conn.ExecuteAsync(
                    "UPDATE org_settings SET anonymous_pull = @on WHERE org_id = @orgId",
                    new { on = on ? 1 : 0, orgId = OrgId });
                Assert.Equal(1, rows);
            }

            Factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(OrgId);
        }

        // 110 % of an egress cap puts the org in downloads_throttled, exactly as the hourly
        // posture recompute would.
        private async Task ThrottleAsync()
        {
            var now = Factory.Services.GetRequiredService<TimeProvider>().GetUtcNow();
            string bucket = new DateTimeOffset(now.Year, now.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUtcIso();
            await using (var conn = await Db.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO usage_hourly (org_id, meter, bucket, quantity, redirect_quantity, request_count, computed_at)
                    VALUES (@orgId, @meter, @bucket, 1100, 0, 1, @bucket)
                    ON CONFLICT (org_id, meter, bucket) DO UPDATE SET quantity = excluded.quantity
                    """,
                    new { orgId = OrgId, meter = UsageCapMeters.EgressBytes, bucket });
            }

            var postures = Factory.Services.GetRequiredService<UsagePostureRepository>();
            await postures.SetCapsAsync(OrgId, new Dictionary<string, long?> { [UsageCapMeters.EgressBytes] = 1000 });
            Assert.Equal(UsagePostures.DownloadsThrottled, await postures.RecomputeForOrgAsync(OrgId));
        }

        public async Task<string> ForeignTokenAsync()
        {
            await using (var conn = await Db.OpenAsync())
            {
                await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, 'globex')", new { id = Guid.NewGuid().ToString("N") });
            }

            return await Factory.CreateToken("pull", org: "globex");
        }

        // A concurrent burst at the package document, each request on its own client so the
        // per-caller limits never share a partition key with the org's own clients.
        public async Task<List<HttpStatusCode>> BurstAsync(Func<HttpClient> client, string? path = null)
        {
            path ??= $"/npm/{Package}";
            var clients = Enumerable.Range(0, Burst).Select(_ => client()).ToList();
            try
            {
                var responses = await Task.WhenAll(clients.Select(c => c.GetAsync(path)));
                var codes = responses.Select(r => r.StatusCode).ToList();
                foreach (var r in responses)
                {
                    r.Dispose();
                }

                return codes;
            }
            finally
            {
                clients.ForEach(c => c.Dispose());
            }
        }

        public async Task AssertOwnClientsServedAsync()
        {
            string own = await Factory.CreateToken("pull");
            using var client = Factory.CreateClientWithBasic(own);
            for (int i = 0; i < 2; i++)
            {
                using var resp = await client.GetAsync($"/npm/{Package}");
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }
        }

        public async ValueTask DisposeAsync() => await Factory.DisposeAsync();
    }

    // Cargo and Hex clients send the token as the whole Authorization value, with no scheme.
    private static HttpClient BareClient(DependablyFactory factory, string token)
    {
        var client = factory.CreateClient();
        Assert.True(client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", token));
        return client;
    }

    private static void AssertAll(IEnumerable<HttpStatusCode> codes, HttpStatusCode expected) =>
        Assert.All(codes, c => Assert.Equal(expected, c));

    private static void AssertBudgetBinds(List<HttpStatusCode> codes)
    {
        Assert.All(codes, c => Assert.True(c is HttpStatusCode.OK or HttpStatusCode.TooManyRequests, $"unexpected {(int)c}"));
        Assert.InRange(codes.Count(c => c == HttpStatusCode.TooManyRequests), 1, Burst - 2);
    }

    // ── Ordinary budget ───────────────────────────────────────────────────────

    [Fact]
    public async Task An_anonymous_burst_never_draws_on_the_tenant_budget_of_an_org_that_refuses_anonymous_pull()
    {
        await using var s = new Scenario(BudgetFactory());
        await s.StartAsync(anonymousPull: false, throttled: false);

        AssertAll(await s.BurstAsync(s.Factory.CreateClient), HttpStatusCode.Unauthorized);
        await s.AssertOwnClientsServedAsync();
    }

    [Fact]
    public async Task An_anonymous_burst_against_an_org_that_allows_anonymous_pull_meets_its_budget()
    {
        await using var s = new Scenario(BudgetFactory());
        await s.StartAsync(anonymousPull: true, throttled: false);

        AssertBudgetBinds(await s.BurstAsync(s.Factory.CreateClient));
    }

    [Fact]
    public async Task Another_orgs_tokens_never_draw_on_the_tenant_budget_of_an_org_that_refuses_anonymous_pull()
    {
        await using var s = new Scenario(BudgetFactory());
        await s.StartAsync(anonymousPull: false, throttled: false);
        string foreign = await s.ForeignTokenAsync();

        AssertAll(await s.BurstAsync(() => s.Factory.CreateClientWithBasic(foreign)), HttpStatusCode.Unauthorized);
        await s.AssertOwnClientsServedAsync();
    }

    [Fact]
    public async Task The_orgs_own_tokens_still_meet_its_budget()
    {
        await using var s = new Scenario(BudgetFactory());
        await s.StartAsync(anonymousPull: false, throttled: false);
        string own = await s.Factory.CreateToken("pull");

        AssertBudgetBinds(await s.BurstAsync(() => s.Factory.CreateClientWithBasic(own)));
    }

    // ── downloads_throttled ───────────────────────────────────────────────────

    [Fact]
    public async Task An_anonymous_burst_never_draws_on_the_throttled_budget_of_an_org_that_refuses_anonymous_pull()
    {
        await using var s = new Scenario(ThrottledFactory());
        await s.StartAsync(anonymousPull: false, throttled: true);

        AssertAll(await s.BurstAsync(s.Factory.CreateClient), HttpStatusCode.Unauthorized);
        await s.AssertOwnClientsServedAsync();
    }

    [Fact]
    public async Task An_anonymous_burst_against_a_throttled_org_that_allows_anonymous_pull_is_throttled()
    {
        await using var s = new Scenario(ThrottledFactory());
        await s.StartAsync(anonymousPull: true, throttled: true);

        AssertBudgetBinds(await s.BurstAsync(s.Factory.CreateClient));
    }

    [Fact]
    public async Task The_orgs_own_bare_cargo_tokens_still_meet_its_throttled_budget()
    {
        await using var s = new Scenario(ThrottledFactory());
        await s.StartAsync(anonymousPull: false, throttled: true);
        string own = await s.Factory.CreateToken("pull");

        AssertBudgetBinds(await s.BurstAsync(() => BareClient(s.Factory, own), "/cargo/config.json"));
    }

    [Fact]
    public async Task A_bare_garbage_burst_never_draws_on_the_throttled_budget_of_an_org_that_refuses_anonymous_pull()
    {
        await using var s = new Scenario(ThrottledFactory());
        await s.StartAsync(anonymousPull: false, throttled: true);

        AssertAll(
            await s.BurstAsync(() => BareClient(s.Factory, "junk-" + Guid.NewGuid().ToString("N")), "/cargo/config.json"),
            HttpStatusCode.Unauthorized);
        await s.AssertOwnClientsServedAsync();
    }
}
