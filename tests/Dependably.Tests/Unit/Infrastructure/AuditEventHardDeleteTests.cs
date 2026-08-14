using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Verifies that <see cref="TenantHardDeleteService"/> pseudonymizes the hard-deleted tenant's
/// <c>audit_event</c> rows. Unlike <c>audit_log</c> (no FK to <c>orgs</c>, erased outright —
/// see <see cref="AuditLogHardDeleteTests"/>), <c>audit_event.org_id</c> carries an
/// <c>ON DELETE SET NULL</c> foreign key: the schema deliberately keeps the row past its org's
/// deletion for forensic purposes, so full erasure would be the wrong shape here. What must
/// still happen is the personal-data half of Art. 17: <c>source_ip</c>/<c>user_agent</c> gone,
/// the forensic skeleton (<c>actor_id</c>, <c>payload</c>) retained. Another tenant's rows must
/// be left untouched.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditEventHardDeleteTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public AuditEventHardDeleteTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    private static TenantHardDeleteService BuildService(IMetadataStore db)
    {
        var clock = TestTime.Frozen(KnownNow);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TENANT_HARD_DELETE_GRACE_DAYS"] = "0" })
            .Build();
        return new TenantHardDeleteService(
            new OrgRepository(db, null, clock),
            new AuditRepository(db, null, clock),
            db,
            new BannerRepository(db, clock),
            config,
            new AirGapMode(config),
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(clock),
            NullLogger<TenantHardDeleteService>.Instance,
            clock);
    }

    private async Task SeedAuditEventAsync(string eventId, string orgId, string actorId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_event (
                event_id, schema_version, event_type, org_id, tenant_resolver,
                actor_type, actor_id, source_ip, user_agent, outcome, payload, occurred_at)
            VALUES (
                @eventId, 1, 'test.event', @orgId, 'single',
                'user', @actorId, '203.0.113.4', 'TestAgent/1.0', 'accepted', '{"k":"v"}',
                '2026-01-01T00:00:00.000Z')
            """,
            new { eventId, orgId, actorId });
    }

    private async Task<(int Count, string? OrgId, string? SourceIp, string? UserAgent, string? ActorId, string Payload)> ReadRowAsync(string eventId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var rows = (await conn.QueryAsync<(string? OrgId, string? SourceIp, string? UserAgent, string? ActorId, string Payload)>(
            "SELECT org_id, source_ip, user_agent, actor_id, payload FROM audit_event WHERE event_id = @eventId",
            new { eventId })).ToList();
        return rows.Count == 0
            ? (0, null, null, null, null, "")
            : (1, rows[0].OrgId, rows[0].SourceIp, rows[0].UserAgent, rows[0].ActorId, rows[0].Payload);
    }

    [Fact]
    public async Task HardDelete_PseudonymizesTenantAuditEventRows_KeepsOtherTenantRowsIntact()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"del-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"keep-b-{Guid.NewGuid():N}");

        await SeedAuditEventAsync("a-event", orgA, "actor-a");
        await SeedAuditEventAsync("b-event", orgB, "actor-b");   // another tenant's row → untouched

        await using (var conn0 = await _fixture.Store.OpenAsync())
        {
            await conn0.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgA });
        }

        await BuildService(_fixture.Store).RunPassAsync(CancellationToken.None);

        // The deleted org's row survives — this is pseudonymization, not deletion — with its
        // personal identifiers gone and its forensic skeleton (actor_id, payload) intact.
        var (aCount, _, aSourceIp, aUserAgent, aActorId, aPayload) = await ReadRowAsync("a-event");
        Assert.Equal(1, aCount);
        Assert.Null(aSourceIp);
        Assert.Null(aUserAgent);
        Assert.Equal("actor-a", aActorId);
        Assert.Equal("""{"k":"v"}""", aPayload);

        // A different tenant's audit_event row is entirely untouched.
        var (bCount, bOrgId, bSourceIp, bUserAgent, _, _) = await ReadRowAsync("b-event");
        Assert.Equal(1, bCount);
        Assert.Equal("203.0.113.4", bSourceIp);
        Assert.Equal("TestAgent/1.0", bUserAgent);
        Assert.Equal(orgB, bOrgId);
    }
}
