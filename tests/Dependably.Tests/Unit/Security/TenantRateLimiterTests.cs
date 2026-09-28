using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Threading.RateLimiting;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Infrastructure.Usage;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The tenant dimension of the global rate limiter: which requests it partitions and under which
/// key (<see cref="RateLimitPartitions.GetTenantPartitionKey"/>), its settings and defaults
/// (<see cref="TenantRateLimitSettings"/>), that one org's budget is shared across every caller
/// and isolated from every other org, and that a rejection names the tenant partition to the
/// denial audit.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantRateLimiterTests
{
    private static DefaultHttpContext Request(
        string path, TenantContext? tenant, bool controllerAction = true, string? user = null, Type? controller = null,
        bool exempt = false)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
        if (tenant is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = tenant;
        }

        if (exempt)
        {
            ctx.Items[TenantRateLimiter.NotTenantTrafficItemKey] = true;
        }

        if (user is not null)
        {
            ctx.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("sub", user)], "Test"));
        }

        var metadata = controllerAction
            ? new EndpointMetadataCollection(new ControllerActionDescriptor
            {
                ControllerTypeInfo = (controller ?? typeof(Dependably.Api.NpmController)).GetTypeInfo(),
            })
            : new EndpointMetadataCollection();
        ctx.SetEndpoint(new Endpoint(_ => Task.CompletedTask, metadata, "test"));
        return ctx;
    }

    private static TenantContext Tenant(string id, string posture = UsagePostures.Normal) =>
        TenantContext.ForTenant(id, id + "-slug", "active", posture);

    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    // ── Partition key ──────────────────────────────────────────────────────────

    [Fact]
    public void Budget_on_partitions_a_protocol_request_by_tenant()
    {
        Assert.Equal("tenant:org-1", RateLimitPartitions.GetTenantPartitionKey(Request("/npm/left-pad", Tenant("org-1")), tenantBudgetEnabled: true));
    }

    [Fact]
    public void Budget_off_leaves_a_normal_tenant_unpartitioned()
    {
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(Request("/npm/left-pad", Tenant("org-1")), tenantBudgetEnabled: false));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Downloads_throttled_uses_the_throttled_partition_whether_or_not_the_budget_is_on(bool budget)
    {
        var ctx = Request("/npm/left-pad", Tenant("org-1", UsagePostures.DownloadsThrottled));

        Assert.Equal("tenant-throttled:org-1", RateLimitPartitions.GetTenantPartitionKey(ctx, budget));
    }

    [Fact]
    public void Uploads_refused_keeps_the_ordinary_budget_partition()
    {
        var ctx = Request("/npm/left-pad", Tenant("org-1", UsagePostures.UploadsRefused));

        Assert.Equal("tenant:org-1", RateLimitPartitions.GetTenantPartitionKey(ctx, tenantBudgetEnabled: true));
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(ctx, tenantBudgetEnabled: false));
    }

    [Theory]
    [InlineData("/api/v1/packages", true)]
    [InlineData("/health", true)]
    [InlineData("/ready/", true)]
    [InlineData("/metrics", true)]
    [InlineData("/assets/index.js", false)]
    public void The_management_plane_probes_and_frontend_are_never_tenant_limited(string path, bool controllerAction)
    {
        // /api/v1/ routes to management controllers; the probes are exempt by path even where a
        // protocol-classified endpoint would answer them.
        var controller = path.StartsWith("/api/v1/", StringComparison.Ordinal) ? typeof(Dependably.Api.SamlController) : null;
        var ctx = Request(path, Tenant("org-1", UsagePostures.DownloadsThrottled), controllerAction, controller: controller);

        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(ctx, tenantBudgetEnabled: true));
    }

    [Fact]
    public void A_management_controller_outside_api_v1_is_never_tenant_limited()
    {
        var ctx = Request("/saml/acs", Tenant("org-1", UsagePostures.DownloadsThrottled), controller: typeof(Dependably.Api.SamlController));

        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(ctx, tenantBudgetEnabled: true));
    }

    [Fact]
    public void Apex_and_unresolved_requests_are_never_tenant_limited()
    {
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(Request("/npm/left-pad", TenantContext.Apex), true));
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(Request("/npm/left-pad", TenantContext.Uninitialized), true));
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(Request("/npm/left-pad", tenant: null), true));
    }

    // ── Traffic the tenant does not serve as its own ───────────────────────────

    [Theory]
    [InlineData(UsagePostures.Normal)]
    [InlineData(UsagePostures.DownloadsThrottled)]
    public void A_request_marked_not_tenant_traffic_is_never_tenant_partitioned(string posture)
    {
        Assert.Null(RateLimitPartitions.GetTenantPartitionKey(
            Request("/npm/left-pad", Tenant("org-1", posture), exempt: true), tenantBudgetEnabled: true));

        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(1, 0, 1, 0));
        for (int i = 0; i < 50; i++)
        {
            var ctx = Request("/npm/a", Tenant("org-1", posture), exempt: true);
            Assert.True(limiter.AttemptAcquire(ctx).IsAcquired);
            Assert.False(ctx.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
        }
    }

    [Theory]
    [InlineData(UsagePostures.Normal, "tenant:org-1")]
    [InlineData(UsagePostures.DownloadsThrottled, "tenant-throttled:org-1")]
    public void An_unmarked_request_is_still_charged_to_the_tenant(string posture, string partition)
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(1, 0, 1, 0));

        Assert.True(limiter.AttemptAcquire(Request("/npm/a", Tenant("org-1", posture))).IsAcquired);
        var second = Request("/npm/a", Tenant("org-1", posture));
        Assert.False(limiter.AttemptAcquire(second).IsAcquired);
        Assert.Equal(partition, second.Items[TenantRateLimiter.RejectedPartitionItemKey]);
    }

    [Fact]
    public void Marked_anonymous_traffic_does_not_drain_the_window_for_the_orgs_own_callers()
    {
        using var chained = TenantRateLimiter.Chain(
            PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("none")),
            new TenantRateLimitSettings(1, 0, 10, 0));

        for (int i = 0; i < 20; i++)
        {
            Assert.True(chained.AttemptAcquire(Request("/npm/a", Tenant("org-1"), exempt: true)).IsAcquired);
        }

        var own = Request("/npm/a", Tenant("org-1"), user: "alice");
        Assert.True(chained.AttemptAcquire(own).IsAcquired);
        Assert.False(own.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
    }

    // ── Settings ───────────────────────────────────────────────────────────────

    [Fact]
    public void Defaults_leave_the_budget_off_and_the_throttle_small()
    {
        var s = TenantRateLimitSettings.Resolve(Cfg());

        Assert.Null(s.BudgetPermits);
        Assert.Equal(TenantRateLimitSettings.DefaultBudgetQueueLimit, s.BudgetQueue);
        Assert.Equal(10, s.ThrottledPermits);
        Assert.Equal(20, s.ThrottledQueue);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("lots")]
    public void A_non_positive_or_unparseable_budget_is_off(string value)
    {
        Assert.Null(TenantRateLimitSettings.Resolve(Cfg(("TENANT_RATE_LIMIT_PERMITS", value))).BudgetPermits);
    }

    [Fact]
    public void Configured_values_are_honoured()
    {
        var s = TenantRateLimitSettings.Resolve(Cfg(
            ("TENANT_RATE_LIMIT_PERMITS", "250"),
            ("TENANT_RATE_LIMIT_QUEUE", "0"),
            ("TENANT_THROTTLED_RATE_LIMIT_PERMITS", "3"),
            ("TENANT_THROTTLED_RATE_LIMIT_QUEUE", "7")));

        Assert.Equal(new TenantRateLimitSettings(250, 0, 3, 7), s);
    }

    [Fact]
    public void A_non_positive_throttle_falls_back_to_the_default_rather_than_switching_it_off()
    {
        Assert.Equal(
            TenantRateLimitSettings.DefaultThrottledPermitLimit,
            TenantRateLimitSettings.Resolve(Cfg(("TENANT_THROTTLED_RATE_LIMIT_PERMITS", "0"))).ThrottledPermits);
    }

    // ── Limiter ────────────────────────────────────────────────────────────────

    [Fact]
    public void One_orgs_budget_is_shared_by_all_its_callers_and_isolated_from_other_orgs()
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(2, 0, 10, 0));

        Assert.True(limiter.AttemptAcquire(Request("/npm/a", Tenant("org-1"), user: "alice")).IsAcquired);
        Assert.True(limiter.AttemptAcquire(Request("/npm/b", Tenant("org-1"), user: "bob")).IsAcquired);

        // A third caller in the same org, on a different token, is over the org's budget.
        var third = Request("/npm/c", Tenant("org-1"), user: "carol");
        Assert.False(limiter.AttemptAcquire(third).IsAcquired);
        Assert.Equal("tenant:org-1", third.Items[TenantRateLimiter.RejectedPartitionItemKey]);

        // Another org is unaffected.
        var other = Request("/npm/a", Tenant("org-2"), user: "alice");
        Assert.True(limiter.AttemptAcquire(other).IsAcquired);
        Assert.False(other.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
    }

    [Fact]
    public void With_the_budget_off_a_normal_org_is_unlimited()
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 1, 0));

        for (int i = 0; i < 50; i++)
        {
            Assert.True(limiter.AttemptAcquire(Request("/npm/a", Tenant("org-1"))).IsAcquired);
        }
    }

    [Fact]
    public void A_throttled_org_draws_on_the_small_throttled_budget_while_a_normal_twin_does_not()
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 1, 0));

        Assert.True(limiter.AttemptAcquire(Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled))).IsAcquired);
        var second = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        Assert.False(second.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
        Assert.False(limiter.AttemptAcquire(second).IsAcquired);
        Assert.Equal("tenant-throttled:org-t", second.Items[TenantRateLimiter.RejectedPartitionItemKey]);

        for (int i = 0; i < 5; i++)
        {
            Assert.True(limiter.AttemptAcquire(Request("/npm/a", Tenant("org-n"))).IsAcquired);
        }
    }

    [Fact]
    public async Task A_throttled_org_queues_within_the_throttled_queue_rather_than_failing_at_once()
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 1, 1));
        var throttled = Tenant("org-t", UsagePostures.DownloadsThrottled);

        using var first = await limiter.AcquireAsync(Request("/npm/a", throttled));
        Assert.True(first.IsAcquired);

        // The second waits in the queue; the third finds the queue full and is refused at once.
        var queued = limiter.AcquireAsync(Request("/npm/a", throttled)).AsTask();
        var overflow = Request("/npm/a", throttled);
        using var refused = await limiter.AcquireAsync(overflow);
        Assert.False(refused.IsAcquired);
        Assert.False(queued.IsCompleted);

        // now-ok: the sliding window replenishes on its own real-time timer, which a fake clock
        // cannot advance; the bound only keeps a regression from hanging the run.
        using var granted = await queued.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None);
        Assert.True(granted.IsAcquired);
    }

    [Fact]
    public void Chained_after_the_per_caller_limiter_the_tenant_budget_still_binds()
    {
        using var chained = TenantRateLimiter.Chain(
            PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("none")),
            new TenantRateLimitSettings(1, 0, 10, 0));

        Assert.True(chained.AttemptAcquire(Request("/npm/a", Tenant("org-1"))).IsAcquired);
        var second = Request("/npm/a", Tenant("org-1"));
        Assert.False(chained.AttemptAcquire(second).IsAcquired);
        Assert.Equal("tenant:org-1", second.Items[TenantRateLimiter.RejectedPartitionItemKey]);
    }

    // ── Attribution through the real RateLimitingMiddleware ────────────────────

    // A host with the production shape: a per-caller link (a no-op unless the test supplies one)
    // chained to the tenant limiter as the global limiter, a "download" endpoint policy on
    // /npm/pkg, an unmetered /npm/unmetered route that only the global limiter bounds, and the
    // rejection callback recording what TenantRateLimiter.AttributeRejection reports — the same
    // call the production callback makes.
    private static async Task<(WebApplication App, List<(string Policy, string Partition)> Rejections)> PipelineAsync(
        TenantRateLimitSettings tenant, int downloadPermits, PartitionedRateLimiter<HttpContext>? perCaller = null)
    {
        var rejections = new List<(string Policy, string Partition)>();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.GlobalLimiter = TenantRateLimiter.Chain(
                perCaller ?? PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("none")),
                tenant);
            o.AddPolicy("download", _ => RateLimitPartition.GetFixedWindowLimiter("all", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = downloadPermits,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0,
            }));
            o.OnRejected = (ctx, _) =>
            {
                lock (rejections)
                {
                    rejections.Add(TenantRateLimiter.AttributeRejection(ctx.HttpContext, 64));
                }

                return ValueTask.CompletedTask;
            };
        });

        var app = builder.Build();
        app.UseRouting();
        app.Use((ctx, next) =>
        {
            ctx.Items[TenantContext.HttpItemsKey] = Tenant("org-t", UsagePostures.DownloadsThrottled);
            return next(ctx);
        });
        app.UseRateLimiter();
        app.MapGet("/npm/pkg", () => "ok")
            .RequireRateLimiting("download")
            .WithMetadata(new ControllerActionDescriptor { ControllerTypeInfo = typeof(Dependably.Api.NpmController).GetTypeInfo() });
        app.MapGet("/npm/unmetered", () => "ok")
            .WithMetadata(new ControllerActionDescriptor { ControllerTypeInfo = typeof(Dependably.Api.NpmController).GetTypeInfo() });
        await app.StartAsync();
        return (app, rejections);
    }

    [Fact]
    public async Task A_queued_tenant_grant_then_an_endpoint_refusal_is_attributed_to_the_endpoint_policy()
    {
        // One throttled permit per second with one queue slot, and a download policy that grants
        // exactly one request. The second request is refused by the tenant limiter on the first
        // try, waits in its queue for the next window and is granted, then meets the exhausted
        // download policy. The refusal is the download policy's; a marker left over from the
        // tenant limiter's first answer would report it as the tenant dimension's.
        var (app, rejections) = await PipelineAsync(new TenantRateLimitSettings(null, 0, 1, 1), downloadPermits: 1);
        await using (app)
        {
            using var client = app.GetTestClient();
            using var first = await client.GetAsync("/npm/pkg");
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);

            using var second = await client.GetAsync("/npm/pkg");

            Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
            var (policy, partition) = Assert.Single(rejections);
            Assert.Equal("download", policy);
            Assert.NotEqual(TenantRateLimiter.PolicyLabel, partition);
        }
    }

    [Fact]
    public async Task A_tenant_refusal_through_the_pipeline_is_attributed_to_the_tenant()
    {
        var (app, rejections) = await PipelineAsync(new TenantRateLimitSettings(null, 0, 1, 0), downloadPermits: 1000);
        await using (app)
        {
            using var client = app.GetTestClient();
            using var first = await client.GetAsync("/npm/pkg");
            using var second = await client.GetAsync("/npm/pkg");

            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);
            Assert.Equal((TenantRateLimiter.PolicyLabel, TenantRateLimiter.PolicyLabel), Assert.Single(rejections));
        }
    }

    // A per-caller link the test can read back: one shared partition, a fixed permit count for
    // the whole run, no queue — the shape of the protocol-default posture.
    private static PartitionedRateLimiter<HttpContext> CountedPerCaller(int permits) =>
        PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetFixedWindowLimiter("caller",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0,
            }));

    [Fact]
    public async Task A_request_the_tenant_refuses_then_queues_costs_the_caller_exactly_one_permit()
    {
        // The caller may make two requests. The first spends the tenant's one throttled permit for
        // this second, so the second is refused by the tenant link on the middleware's first try
        // and waits in its queue. That wait must reuse the per-caller permit the first try was
        // granted: taking another would spend the caller's budget twice for one request and here,
        // with it exhausted, refuse on the per-caller link a request its limit had admitted —
        // attributed to the tenant, whose refusal was not the final one.
        var perCaller = CountedPerCaller(permits: 2);
        var (app, rejections) = await PipelineAsync(
            new TenantRateLimitSettings(null, 0, 1, 1), downloadPermits: 1000, perCaller);
        await using (app)
        {
            using var client = app.GetTestClient();
            using var first = await client.GetAsync("/npm/unmetered");
            using var second = await client.GetAsync("/npm/unmetered");

            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            Assert.Equal(HttpStatusCode.OK, second.StatusCode);
            Assert.Empty(rejections);
            var stats = perCaller.GetStatistics(new DefaultHttpContext());
            Assert.NotNull(stats);
            Assert.Equal(2, stats.TotalSuccessfulLeases);
            Assert.Equal(0, stats.TotalFailedLeases);
            Assert.Equal(0, stats.CurrentAvailablePermits);

            // The caller's budget is now spent: the next refusal is the per-caller link's and is
            // reported as the global default, never as the tenant dimension.
            using var third = await client.GetAsync("/npm/unmetered");

            Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
            var (policy, partition) = Assert.Single(rejections);
            Assert.Equal("unknown", policy);
            Assert.NotEqual(TenantRateLimiter.PolicyLabel, partition);
        }
    }

    [Fact]
    public async Task A_per_caller_refusal_after_an_earlier_tenant_refusal_is_attributed_to_the_caller()
    {
        // The marker an earlier pass's tenant refusal left on the request must not survive a later
        // pass that the per-caller link refuses before the tenant link is consulted.
        using var chained = TenantRateLimiter.Chain(CountedPerCaller(permits: 1), new TenantRateLimitSettings(null, 0, 10, 0));
        Assert.True(chained.AttemptAcquire(Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled))).IsAcquired);

        var ctx = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        ctx.Items[TenantRateLimiter.RejectedPartitionItemKey] = "tenant-throttled:org-t";
        using var lease = await chained.AcquireAsync(ctx);

        Assert.False(lease.IsAcquired);
        Assert.False(ctx.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
        Assert.NotEqual(TenantRateLimiter.PolicyLabel, TenantRateLimiter.AttributeRejection(ctx, 64).Policy);
    }

    [Fact]
    public async Task A_tenant_refusal_on_both_passes_charges_one_per_caller_permit_and_names_the_tenant()
    {
        var perCaller = CountedPerCaller(permits: 5);
        using var chained = TenantRateLimiter.Chain(perCaller, new TenantRateLimitSettings(null, 0, 1, 0));
        Assert.True(chained.AttemptAcquire(Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled))).IsAcquired);

        var ctx = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        Assert.False(chained.AttemptAcquire(ctx).IsAcquired);
        using var lease = await chained.AcquireAsync(ctx);

        Assert.False(lease.IsAcquired);
        Assert.Equal((TenantRateLimiter.PolicyLabel, TenantRateLimiter.PolicyLabel), TenantRateLimiter.AttributeRejection(ctx, 64));
        Assert.Equal(2, perCaller.GetStatistics(ctx)!.TotalSuccessfulLeases);
    }

    [Fact]
    public async Task An_endpoint_policy_queueing_the_request_costs_the_tenant_exactly_one_permit()
    {
        // The endpoint policy admits one request at a time and queues one more. While the first
        // is in flight the second passes the global chain on the middleware's first try, is
        // refused by the endpoint policy, has its global lease disposed and waits on both again.
        // The tenant link already charged it on the first try; the waiting pass must not charge
        // it again.
        var tenantLink = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 5, 0));
        var endpoint = new ConcurrencyLimiter(new ConcurrencyLimiterOptions
        {
            PermitLimit = 1,
            QueueLimit = 1,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        });
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.GlobalLimiter = TenantRateLimiter.Chain(
                PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("none")),
                tenantLink);
            o.AddPolicy("queued", _ => RateLimitPartition.Get("all", _ => endpoint));
        });

        var app = builder.Build();
        app.UseRouting();
        app.Use((ctx, next) =>
        {
            ctx.Items[TenantContext.HttpItemsKey] = Tenant("org-t", UsagePostures.DownloadsThrottled);
            return next(ctx);
        });
        app.UseRateLimiter();
        app.MapGet("/npm/queued", async () =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    entered.SetResult();
                    await release.Task;
                }

                return "ok";
            })
            .RequireRateLimiting("queued")
            .WithMetadata(new ControllerActionDescriptor { ControllerTypeInfo = typeof(Dependably.Api.NpmController).GetTypeInfo() });
        await app.StartAsync();
        await using (app)
        {
            using var client = app.GetTestClient();
            var first = client.GetAsync("/npm/queued");
            // now-ok: awaiting real async completion on the server's thread; the bound only keeps
            // a regression from hanging the run.
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TimeProvider.System, CancellationToken.None);
            var second = client.GetAsync("/npm/queued");
            for (int i = 0; i < 1000 && endpoint.GetStatistics()!.CurrentQueuedCount == 0 && !second.IsCompleted; i++)
            {
                // now-ok: polling for the second request to reach the endpoint queue on another thread.
                await Task.Delay(TimeSpan.FromMilliseconds(10), TimeProvider.System, CancellationToken.None);
            }

            Assert.Equal(1, endpoint.GetStatistics()!.CurrentQueuedCount);
            release.SetResult();
            using var firstResponse = await first;
            using var secondResponse = await second;

            Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
            Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
            var stats = tenantLink.GetStatistics(Request("/npm/queued", Tenant("org-t", UsagePostures.DownloadsThrottled)));
            Assert.NotNull(stats);
            Assert.Equal(2, stats.TotalSuccessfulLeases);
            Assert.Equal(0, stats.TotalFailedLeases);
        }
    }

    [Fact]
    public async Task A_charge_is_honoured_only_for_the_request_the_tenant_charged()
    {
        var tenantLink = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 1, 0));
        using var chained = TenantRateLimiter.Chain(
            PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("none")), tenantLink);
        var charged = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        chained.AttemptAcquire(charged).Dispose();

        // Another request finds the org's one permit spent, on either pass, and is named the
        // tenant's refusal.
        var other = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        Assert.False(chained.AttemptAcquire(other).IsAcquired);
        using var otherWait = await chained.AcquireAsync(other);
        Assert.False(otherWait.IsAcquired);
        Assert.Equal(TenantRateLimiter.PolicyLabel, TenantRateLimiter.AttributeRejection(other, 64).Policy);

        // The request the tenant already charged is granted again on its waiting pass.
        using var chargedWait = await chained.AcquireAsync(charged);
        Assert.True(chargedWait.IsAcquired);
        Assert.Equal(1, tenantLink.GetStatistics(charged)!.TotalSuccessfulLeases);
    }

    [Fact]
    public void A_zero_permit_probe_pays_for_nothing_a_later_acquisition_can_reuse()
    {
        var perCaller = CountedPerCaller(permits: 5);
        using var chained = TenantRateLimiter.Chain(perCaller, new TenantRateLimitSettings(null, 0, 1, 0));
        Assert.True(chained.AttemptAcquire(Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled))).IsAcquired);

        // A zero-permit probe the tenant refuses leaves nothing a real acquisition may stand on.
        var ctx = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        Assert.False(chained.AttemptAcquire(ctx, 0).IsAcquired);
        Assert.False(chained.AttemptAcquire(ctx, 1).IsAcquired);

        Assert.Equal(3, perCaller.GetStatistics(ctx)!.TotalSuccessfulLeases);
    }

    [Fact]
    public void A_granted_lease_clears_an_earlier_refusal_marker()
    {
        using var limiter = TenantRateLimiter.Create(new TenantRateLimitSettings(null, 0, 1, 0));
        var ctx = Request("/npm/a", Tenant("org-t", UsagePostures.DownloadsThrottled));
        ctx.Items[TenantRateLimiter.RejectedPartitionItemKey] = "tenant-throttled:org-t";

        Assert.True(limiter.AttemptAcquire(ctx).IsAcquired);

        Assert.False(ctx.Items.ContainsKey(TenantRateLimiter.RejectedPartitionItemKey));
    }

    // ── Denial audit ───────────────────────────────────────────────────────────

    [Fact]
    public async Task A_tenant_rejection_is_audited_under_the_tenant_partition()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        var clock = TestTime.Frozen();
        var coalescer = new AuthDenialAuditCoalescer(clock);
        var flusher = new AuthDenialAuditFlushService(
            coalescer,
            new AuditRepository(db, activityWriter: null, time: clock),
            clock,
            NullLogger<AuthDenialAuditFlushService>.Instance,
            window: TimeSpan.FromSeconds(60));

        var ctx = Request("/npm/left-pad", Tenant("org-1", UsagePostures.DownloadsThrottled), user: "alice");
        ctx.RequestServices = new ServiceCollection().AddSingleton(coalescer).BuildServiceProvider();
        ctx.Items[TenantRateLimiter.RejectedPartitionItemKey] = "tenant-throttled:org-1";

        RateLimitDenialAuditRecorder.Record(ctx, TenantRateLimiter.PolicyLabel, 64, useRedis: false);
        await flusher.FlushWindowAsync(CancellationToken.None);

        await using var conn = await db.OpenAsync();
        string detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM audit_log WHERE action = 'ratelimit.rejected'") ?? "{}";
        var root = JsonDocument.Parse(detail).RootElement;
        Assert.Equal("tenant", root.GetProperty("policy").GetString());
        Assert.Equal("tenant-throttled:org-1", root.GetProperty("partition").GetString());
    }
}
