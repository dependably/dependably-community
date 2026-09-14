using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// The window flusher is the only thing that turns accumulated denial counts into audit rows, so
/// these pin the two properties a wiring change depends on: the count reaches the row, and the row
/// is attributed to the tenant that produced it rather than to whichever tenant shared the
/// attacker's address first. The shutdown case matters on its own — counts live only in this
/// process's memory, so a drain that does not run on SIGTERM silently loses the last window of a
/// deploy, which is exactly when a rolling restart is cycling replicas.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuthDenialAuditFlushServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static AuthDenialKey Key(
        string partition,
        string? org = "org-1",
        string reason = "invalid",
        string? ecosystem = "npm",
        string? policy = null,
        string route = "/npm/{*path}") =>
        new()
        {
            Action = "auth.token.rejected",
            OrgId = org,
            Partition = partition,
            Ecosystem = ecosystem,
            Policy = policy,
            Reason = reason,
            Route = route,
        };

    private (AuthDenialAuditCoalescer Accumulator, AuthDenialAuditFlushService Service) Build()
    {
        var accumulator = new AuthDenialAuditCoalescer(_clock);
        var service = new AuthDenialAuditFlushService(
            accumulator,
            new AuditRepository(_db, activityWriter: null, time: _clock),
            _clock,
            NullLogger<AuthDenialAuditFlushService>.Instance,
            window: TimeSpan.FromSeconds(60));
        return (accumulator, service);
    }

    private async Task<List<AuditRow>> ReadRowsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<AuditRow>(
            """
            SELECT scope AS Scope, org_id AS OrgId, action AS Action, ecosystem AS Ecosystem,
                   detail AS Detail, source_ip AS SourceIp, actor_id AS ActorId, actor_kind AS ActorKind
            FROM audit_log
            ORDER BY id
            """);
        return rows.ToList();
    }

    private static JsonElement Detail(AuditRow row) =>
        JsonDocument.Parse(row.Detail ?? "{}").RootElement;

    [Fact]
    public async Task OneRowPerKeyPerWindowCarriesTheCount()
    {
        var (accumulator, service) = Build();

        for (int i = 0; i < 37; i++)
        {
            accumulator.Record(Key("2001:db8::/64"), sourceIp: "2001:db8::1");
        }

        accumulator.Record(Key("ip-2", reason: "tenant_mismatch"), sourceIp: "198.51.100.7");

        await service.FlushWindowAsync(CancellationToken.None);

        var rows = await ReadRowsAsync();
        Assert.Equal(2, rows.Count);

        var burst = rows.Single(r => Detail(r).GetProperty("partition").GetString() == "2001:db8::/64");
        Assert.Equal("tenant", burst.Scope);
        Assert.Equal("org-1", burst.OrgId);
        Assert.Equal("auth.token.rejected", burst.Action);
        // The ecosystem lands in its own column, not only in the payload: the personal-data sweep
        // nulls detail and source_ip at the configured horizon, and a row whose whole meaning
        // lived in detail would read as an actionless denial afterwards.
        Assert.Equal("npm", burst.Ecosystem);
        Assert.Equal("2001:db8::1", burst.SourceIp);
        // Actor-less by construction: the partition dimension carries whatever identity the
        // denial had, and no actorId means no fabricated actor_kind beside it.
        Assert.Null(burst.ActorId);
        Assert.Null(burst.ActorKind);

        var detail = Detail(burst);
        Assert.Equal(37, detail.GetProperty("count").GetInt64());
        Assert.Equal("invalid", detail.GetProperty("reason").GetString());
        Assert.Equal("/npm/{*path}", detail.GetProperty("route").GetString());
        Assert.Equal(Environment.MachineName, detail.GetProperty("replica").GetString());

        var single = rows.Single(r => Detail(r).GetProperty("partition").GetString() == "ip-2");
        Assert.Equal(1, Detail(single).GetProperty("count").GetInt64());
        Assert.Equal("tenant_mismatch", Detail(single).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task TwoOrgsSharingOnePartitionAreWrittenAsTwoCorrectlyAttributedRows()
    {
        var (accumulator, service) = Build();

        accumulator.Record(Key("2001:db8::/64", org: "org-a"), sourceIp: "2001:db8::1");
        accumulator.Record(Key("2001:db8::/64", org: "org-a"), sourceIp: "2001:db8::1");
        accumulator.Record(Key("2001:db8::/64", org: "org-b"), sourceIp: "2001:db8::1");

        await service.FlushWindowAsync(CancellationToken.None);

        var rows = await ReadRowsAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal(2, Detail(rows.Single(r => r.OrgId == "org-a")).GetProperty("count").GetInt64());
        Assert.Equal(1, Detail(rows.Single(r => r.OrgId == "org-b")).GetProperty("count").GetInt64());
        Assert.All(rows, r => Assert.Equal("tenant", r.Scope));
    }

    [Fact]
    public async Task ATallyWithNoResolvedTenantIsWrittenAsASystemScopeRow()
    {
        var (accumulator, service) = Build();

        accumulator.Record(Key("ip-1", org: null), sourceIp: "198.51.100.7");

        await service.FlushWindowAsync(CancellationToken.None);

        var row = Assert.Single(await ReadRowsAsync());
        // A tenant-scope row with a NULL org is readable from neither the tenant audit page nor
        // that tenant's SIEM feed, so an org-less denial has to land in the system realm instead.
        Assert.Equal("system", row.Scope);
        Assert.Null(row.OrgId);
        Assert.Equal("198.51.100.7", row.SourceIp);
        Assert.Equal(1, Detail(row).GetProperty("count").GetInt64());
    }

    [Fact]
    public async Task ThePayloadWindowBoundsAreTheExactClockInstants()
    {
        var (accumulator, service) = Build();

        accumulator.Record(Key("ip-1"));
        _clock.Advance(TimeSpan.FromSeconds(60));

        await service.FlushWindowAsync(CancellationToken.None);

        var detail = Detail(Assert.Single(await ReadRowsAsync()));
        Assert.Equal(TestTime.KnownNow.ToUtcIsoMillis(), detail.GetProperty("window_start").GetString());
        Assert.Equal(TestTime.KnownNow.AddSeconds(60).ToUtcIsoMillis(), detail.GetProperty("window_end").GetString());
    }

    [Fact]
    public async Task ShutdownDrainsThePendingWindowInsteadOfLosingIt()
    {
        var (accumulator, service) = Build();
        using var stopping = new CancellationTokenSource();

        var loop = service.ExecuteAsyncForTests(stopping.Token);

        for (int i = 0; i < 4; i++)
        {
            accumulator.Record(Key("ip-1"), sourceIp: "198.51.100.7");
        }

        // No tick has fired — the window period is driven by a fake clock nobody advanced — so
        // everything recorded above is still only in memory when the host signals shutdown.
        Assert.Empty(await ReadRowsAsync());

        await stopping.CancelAsync();
        await loop;

        var row = Assert.Single(await ReadRowsAsync());
        Assert.Equal(4, Detail(row).GetProperty("count").GetInt64());
    }

    [Fact]
    public async Task AFoldedOverflowBucketIsWrittenWithItsCountAndIsIdentifiableAsFolded()
    {
        var (accumulator, service) = Build();

        for (int i = 0; i < AuthDenialAuditCoalescer.CountKeyCap; i++)
        {
            accumulator.Record(Key($"ip-{i}"));
        }

        for (int i = 0; i < 9; i++)
        {
            accumulator.Record(Key($"spray-{i}"), sourceIp: "203.0.113.9");
        }

        await service.FlushWindowAsync(CancellationToken.None);

        var rows = await ReadRowsAsync();
        var folded = rows.Single(
            r => Detail(r).GetProperty("partition").GetString() == AuthDenialAuditCoalescer.OverflowPartition);

        Assert.Equal(9, Detail(folded).GetProperty("count").GetInt64());
        Assert.Equal("org-1", folded.OrgId);
        Assert.Equal("npm", folded.Ecosystem);
        Assert.Equal("invalid", Detail(folded).GetProperty("reason").GetString());
    }

    [Fact]
    public async Task AnEmptyWindowWritesNothing()
    {
        var (_, service) = Build();

        await service.FlushWindowAsync(CancellationToken.None);

        Assert.Empty(await ReadRowsAsync());
    }

    private sealed record AuditRow(
        string Scope,
        string? OrgId,
        string Action,
        string? Ecosystem,
        string? Detail,
        string? SourceIp,
        string? ActorId,
        string? ActorKind);
}
