using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.SystemEvents;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the <c>tenant.hard_deleted</c> operator-Slack producer:
/// <see cref="TenantHardDeleteService"/> reads the tenant's slug before the row is deleted and
/// notifies with no actor (a background sweep, not an operator action) — exactly one
/// <see cref="SystemEventRecord"/> per hard-deleted tenant.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantHardDeleteServiceSystemEventTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    public TenantHardDeleteServiceSystemEventTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    private sealed class RecordingSystemEventNotifier : ISystemEventNotifier
    {
        public List<SystemEventRecord> Records { get; } = [];
        public void Notify(SystemEventRecord record) => Records.Add(record);
    }

    private static TenantHardDeleteService BuildService(
        IMetadataStore db, TimeProvider clock, ISystemEventNotifier notifier)
    {
        var orgs = new OrgRepository(db, null, clock);
        var audit = new AuditRepository(db, null, clock);
        var banners = new BannerRepository(db, clock);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TENANT_HARD_DELETE_GRACE_DAYS"] = "0",
            })
            .Build();
        return new TenantHardDeleteService(
            orgs, audit, db, banners, config,
            new AirGapMode(config),
            new InProcessDistributedLock(clock),
            NullLogger<TenantHardDeleteService>.Instance,
            clock,
            notifier);
    }

    [Fact]
    public async Task RunPassAsync_HardDeletesExpiredTenant_NotifiesWithSlugAndNoActor()
    {
        var clock = TestTime.Frozen(KnownNow);
        string slug = $"hd-{Guid.NewGuid():N}"[..12];
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
                new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgId });
        }

        var notifier = new RecordingSystemEventNotifier();
        var svc = BuildService(_fixture.Store, clock, notifier);

        await svc.RunPassAsync(CancellationToken.None);

        var record = Assert.Single(notifier.Records);
        Assert.Equal("tenant.hard_deleted", record.Action);
        Assert.Equal(slug, record.TenantSlug);
        Assert.Null(record.Actor);
        Assert.Null(record.TenantName);
    }

    [Fact]
    public async Task RunPassAsync_NoExpiredTenants_NoNotification()
    {
        var clock = TestTime.Frozen(KnownNow);
        var notifier = new RecordingSystemEventNotifier();
        var svc = BuildService(_fixture.Store, clock, notifier);

        await svc.RunPassAsync(CancellationToken.None);

        Assert.Empty(notifier.Records);
    }
}
