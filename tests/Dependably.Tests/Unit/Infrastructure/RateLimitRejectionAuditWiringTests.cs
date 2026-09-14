using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="RateLimitDenialAuditRecorder.Record"/> is the single seam between the
/// rate limiter's global <c>OnRejected</c> callback and the count-preserving denial accumulator. It
/// never writes an audit row itself — it only folds one rejection into
/// <see cref="AuthDenialAuditCoalescer"/> — so these tests drive it directly and then flush the
/// accumulator to assert what actually lands in <c>audit_log</c>, which is the only place a wrong
/// partition derivation, a dropped org, or a partition-form source_ip would be visible.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RateLimitRejectionAuditWiringTests : IAsyncLifetime
{
    private const int Ipv6Prefix = IpAddressExtensions.DefaultIpv6PartitionPrefixBits;

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private (AuthDenialAuditCoalescer Coalescer, AuthDenialAuditFlushService Flusher) Build()
    {
        var coalescer = new AuthDenialAuditCoalescer(_clock);
        var flusher = new AuthDenialAuditFlushService(
            coalescer,
            new AuditRepository(_db, activityWriter: null, time: _clock),
            _clock,
            NullLogger<AuthDenialAuditFlushService>.Instance,
            window: TimeSpan.FromSeconds(60));
        return (coalescer, flusher);
    }

    private static DefaultHttpContext BuildContext(
        AuthDenialAuditCoalescer coalescer,
        string path,
        string remoteIp,
        TenantContext? tenantContext = null,
        ClaimsPrincipal? user = null,
        string? authorizationHeader = null,
        string? routeTemplate = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(coalescer);

        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Path = path;
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);

        if (user is not null)
        {
            ctx.User = user;
        }

        if (authorizationHeader is not null)
        {
            ctx.Request.Headers.Authorization = authorizationHeader;
        }

        if (tenantContext is not null)
        {
            ctx.Items[TenantContext.HttpItemsKey] = tenantContext;
        }

        if (routeTemplate is not null)
        {
            ctx.SetEndpoint(new RouteEndpoint(
                requestDelegate: _ => Task.CompletedTask,
                RoutePatternFactory.Parse(routeTemplate),
                order: 0,
                metadata: new EndpointMetadataCollection(),
                displayName: "test-endpoint"));
        }

        return ctx;
    }

    private static ClaimsPrincipal AuthenticatedUser(string sub) =>
        new(new ClaimsIdentity([new Claim("sub", sub)], authenticationType: "Test"));

    private async Task<List<AuditRow>> ReadRowsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<AuditRow>(
            """
            SELECT scope AS Scope, org_id AS OrgId, action AS Action, ecosystem AS Ecosystem,
                   detail AS Detail, source_ip AS SourceIp
            FROM audit_log
            ORDER BY id
            """);
        return rows.ToList();
    }

    private static JsonElement Detail(AuditRow row) => JsonDocument.Parse(row.Detail ?? "{}").RootElement;

    [Fact]
    public async Task BurstOfRejectionsOnOnePartitionProducesOneRowCarryingTheCount()
    {
        var (coalescer, flusher) = Build();
        var tenant = TenantContext.ForTenant("org-1", "org-one");

        for (int i = 0; i < 50; i++)
        {
            var ctx = BuildContext(
                coalescer, "/npm/left-pad", "203.0.113.9",
                tenantContext: tenant, routeTemplate: "/npm/{**path}");
            RateLimitDenialAuditRecorder.Record(ctx, "download", Ipv6Prefix, useRedis: false);
        }

        await flusher.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        Assert.Equal("ratelimit.rejected", row.Action);
        Assert.Equal("org-1", row.OrgId);
        Assert.Equal("npm", row.Ecosystem);

        var detail = Detail(row);
        Assert.Equal(50, detail.GetProperty("count").GetInt64());
        Assert.Equal("rate_limited", detail.GetProperty("reason").GetString());
        Assert.Equal("download", detail.GetProperty("policy").GetString());
        Assert.Equal("/npm/{**path}", detail.GetProperty("route").GetString());
        Assert.Equal("ip:203.0.113.9", detail.GetProperty("partition").GetString());
    }

    [Fact]
    public async Task TwoOrgsSharingOnePartitionInOneWindowProduceTwoCorrectlyAttributedRows()
    {
        var (coalescer, flusher) = Build();

        var ctxA = BuildContext(
            coalescer, "/npm/left-pad", "203.0.113.9",
            tenantContext: TenantContext.ForTenant("org-a", "a"), routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(ctxA, "download", Ipv6Prefix, useRedis: false);
        RateLimitDenialAuditRecorder.Record(ctxA, "download", Ipv6Prefix, useRedis: false);

        var ctxB = BuildContext(
            coalescer, "/npm/left-pad", "203.0.113.9",
            tenantContext: TenantContext.ForTenant("org-b", "b"), routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(ctxB, "download", Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var rows = await ReadRowsAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal(2, Detail(rows.Single(r => r.OrgId == "org-a")).GetProperty("count").GetInt64());
        Assert.Equal(1, Detail(rows.Single(r => r.OrgId == "org-b")).GetProperty("count").GetInt64());
        Assert.All(rows, r => Assert.Equal("tenant", r.Scope));
    }

    /// <summary>
    /// A management-scope rejection (an authenticated <c>/api/v1/*</c> request) and a
    /// protocol-scope rejection (download) from the SAME caller derive DIFFERENT partition keys,
    /// because the management branch prefers the raw Authorization header
    /// (<see cref="RateLimitPartitions.GetManagementPartitionKey"/>) while the protocol branch
    /// never reads it (<see cref="RateLimitPartitions.GetPartitionKey"/>). A wiring bug that
    /// always used one derivation for both would collapse this to a single "user:svc-1" partition
    /// for both rows — this test fails on that bug.
    /// </summary>
    [Fact]
    public async Task ManagementScopeAndDownloadScopeRejectionsDeriveDifferentPartitionKeys()
    {
        var (coalescer, flusher) = Build();
        var user = AuthenticatedUser("svc-1");

        var managementCtx = BuildContext(
            coalescer, "/api/v1/orgs", "198.51.100.5",
            user: user, authorizationHeader: "Bearer ci-automation-token");
        RateLimitDenialAuditRecorder.Record(managementCtx, "unknown", Ipv6Prefix, useRedis: false);

        var downloadCtx = BuildContext(
            coalescer, "/npm/left-pad", "198.51.100.5",
            user: user, authorizationHeader: "Bearer ci-automation-token",
            routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(downloadCtx, "download", Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var rows = await ReadRowsAsync();
        Assert.Equal(2, rows.Count);
        var partitions = rows.Select(r => Detail(r).GetProperty("partition").GetString()).ToList();
        Assert.Equal(2, partitions.Distinct().Count());

        string expectedManagementPartition = RateLimitPartitions.GetManagementPartitionKey(managementCtx, Ipv6Prefix);
        string expectedDownloadPartition = RateLimitPartitions.GetPartitionKey(downloadCtx, Ipv6Prefix);
        Assert.StartsWith("token:", expectedManagementPartition);
        Assert.Equal("user:svc-1", expectedDownloadPartition);
        Assert.Contains(expectedManagementPartition, partitions);
        Assert.Contains(expectedDownloadPartition, partitions);
    }

    [Fact]
    public async Task ApexOrSystemScopeRejectionIsWrittenViaLogSystemAsync()
    {
        var (coalescer, flusher) = Build();

        var ctx = BuildContext(
            coalescer, "/api/v1/bootstrap", "198.51.100.7",
            tenantContext: TenantContext.Apex);
        RateLimitDenialAuditRecorder.Record(ctx, "anon", Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        Assert.Equal("system", row.Scope);
        Assert.Null(row.OrgId);
        Assert.Equal("198.51.100.7", row.SourceIp);
    }

    /// <summary>
    /// <c>source_ip</c> on the flushed row is the FULL address of the first rejection folded into
    /// the key, never the collapsed IPv6 <c>/64</c> partition form two addresses in that block
    /// share. A wiring bug that passed the partition string as <c>sourceIp</c> instead of the raw
    /// remote address fails this.
    /// </summary>
    [Fact]
    public async Task SourceIpIsTheFirstFullAddressNotThePartitionForm()
    {
        var (coalescer, flusher) = Build();
        var tenant = TenantContext.ForTenant("org-1", "org-one");

        var first = BuildContext(
            coalescer, "/npm/left-pad", "2001:db8::1",
            tenantContext: tenant, routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(first, "download", Ipv6Prefix, useRedis: false);

        // A second address in the SAME /64 — same partition, different full address. Must not
        // overwrite the first-seen source_ip.
        var second = BuildContext(
            coalescer, "/npm/left-pad", "2001:db8::dead:beef",
            tenantContext: tenant, routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(second, "download", Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        Assert.Equal(2, Detail(row).GetProperty("count").GetInt64());
        Assert.Equal("2001:db8::1", row.SourceIp);
        Assert.NotEqual("2001:db8::/64", row.SourceIp);
        Assert.DoesNotContain('/', row.SourceIp ?? string.Empty);
    }

    /// <summary>
    /// The <c>import</c> policy routes under <c>/api/v1/admin/upload</c> — a management-plane
    /// PATH — but its own <c>AddPolicy("import", …)</c> closure keys on
    /// <see cref="RateLimitPartitions.GetPartitionKey"/> (user sub, falling back to IP), never
    /// the management token/user/IP derivation. A dispatch that branches on path shape rather
    /// than the policy name itself gets this backwards and records a partition <c>import</c>
    /// never actually bucketed on — this pins the corrected, policy-keyed derivation.
    /// </summary>
    [Fact]
    public async Task ImportPolicyUnderApiV1PartitionsLikeItsOwnPolicyNotLikeManagement()
    {
        var (coalescer, flusher) = Build();
        var user = AuthenticatedUser("import-user");

        var ctx = BuildContext(
            coalescer, "/api/v1/admin/upload", "203.0.113.20",
            user: user, authorizationHeader: "Bearer some-token");
        RateLimitDenialAuditRecorder.Record(ctx, "import", Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        string partition = Detail(row).GetProperty("partition").GetString()!;

        Assert.Equal(RateLimitPartitions.GetPartitionKey(ctx, Ipv6Prefix), partition);
        Assert.Equal("user:import-user", partition);
        Assert.False(partition.StartsWith("token:", StringComparison.Ordinal));
    }

    /// <summary>
    /// The <c>metadata</c> and <c>anon</c> policies bucket on the bare source IP with NO
    /// <c>"ip:"</c> prefix (<c>AddMetadataLimiter</c>/<c>AddAnonymousProbeLimiter</c>) —
    /// authentication never changes their bucket. A dispatch that falls back to
    /// <see cref="RateLimitPartitions.GetPartitionKey"/> for "everything not management" records
    /// <c>"ip:203.0.113.30"</c> instead, which is a partition string the real limiter never used.
    /// </summary>
    [Theory]
    [InlineData("metadata", "/npm/left-pad")]
    [InlineData("anon", "/api/v1/bootstrap")]
    public async Task MetadataAndAnonPartitionOnTheBareSourceIpWithNoPrefix(string policy, string path)
    {
        var (coalescer, flusher) = Build();

        var ctx = BuildContext(coalescer, path, "203.0.113.30", routeTemplate: "/npm/{**path}");
        RateLimitDenialAuditRecorder.Record(ctx, policy, Ipv6Prefix, useRedis: false);

        await flusher.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        string partition = Detail(row).GetProperty("partition").GetString()!;

        Assert.Equal("203.0.113.30", partition);
        Assert.DoesNotContain(':', partition);
    }

    /// <summary>
    /// login/invite/token-create are in-process bare-IP UNLESS a Redis connection string is
    /// configured, in which case <c>RedisRateLimitPolicy.GetPartition</c> buckets on
    /// <c>"{ip}:{policyName}"</c> instead. The recorder must reproduce whichever one is actually
    /// live — a fixed derivation here would silently mismatch the moment an operator turns Redis
    /// on (or off).
    /// </summary>
    [Fact]
    public async Task LoginPartitionsDifferentlyInProcessVersusRedisBacked()
    {
        var (coalescer, flusher) = Build();

        var inProcessCtx = BuildContext(coalescer, "/api/v1/auth/login", "203.0.113.40");
        RateLimitDenialAuditRecorder.Record(inProcessCtx, "login", Ipv6Prefix, useRedis: false);
        await flusher.FlushWindowAsync(CancellationToken.None);
        var inProcessRow = Assert.Single(await ReadRowsAsync());
        Assert.Equal("203.0.113.40", Detail(inProcessRow).GetProperty("partition").GetString());

        var redisCtx = BuildContext(coalescer, "/api/v1/auth/login", "203.0.113.40");
        RateLimitDenialAuditRecorder.Record(redisCtx, "login", Ipv6Prefix, useRedis: true);
        await flusher.FlushWindowAsync(CancellationToken.None);

        // Both rows are asserted as a set. ReadRowsAsync orders by `id`, which is a fresh GUID per
        // row, so positional selection (`.Skip(1)`) picks whichever of the two happened to sort
        // second — the assertion passed or failed on the GUIDs, not on the partitioning.
        string[] partitions = [.. (await ReadRowsAsync())
            .Select(r => Detail(r).GetProperty("partition").GetString()!)
            .OrderBy(pt => pt, StringComparer.Ordinal)];
        Assert.Equal(["203.0.113.40", "203.0.113.40:login"], partitions);
    }

    private sealed record AuditRow(
        string Scope,
        string? OrgId,
        string Action,
        string? Ecosystem,
        string? Detail,
        string? SourceIp);
}
