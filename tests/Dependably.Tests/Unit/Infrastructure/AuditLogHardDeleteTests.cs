using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Verifies that <see cref="TenantHardDeleteService"/> erases the tenant-scoped
/// <c>audit_log</c> rows for a hard-deleted tenant. Because <c>audit_log.org_id</c> carries no
/// FK to <c>orgs</c> (the forensic-retention design), the DELETE FROM orgs cascade does not
/// remove them — the person's source IPs and email/NameID-bearing detail would otherwise
/// survive after the operator UI reports the tenant permanently deleted. Operator
/// <c>scope='system'</c> rows and another tenant's rows must be left untouched.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditLogHardDeleteTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public AuditLogHardDeleteTests(InMemoryDbFixture fixture) => _fixture = fixture;

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

    private async Task SeedAuditAsync(string id, string scope, string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO audit_log (id, scope, org_id, actor_id, action, detail, source_ip) VALUES (@id, @scope, @orgId, 'actor', 'act', '{\"email\":\"a@b.com\"}', '203.0.113.4')",
            new { id, scope, orgId });
    }

    private async Task<int> CountAsync(string id)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE id = @id", new { id });
    }

    [Fact]
    public async Task HardDelete_ErasesTenantAuditRows_KeepsSystemAndOtherTenantRows()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"del-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"keep-b-{Guid.NewGuid():N}");

        await SeedAuditAsync("a-tenant", "tenant", orgA);   // tenant business row for the deleted org → erased
        await SeedAuditAsync("a-system", "system", orgA);   // operator lifecycle row for the same org → retained
        await SeedAuditAsync("b-tenant", "tenant", orgB);   // another tenant's row → untouched

        await using var conn0 = await _fixture.Store.OpenAsync();
        await conn0.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
            new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgA });

        await BuildService(_fixture.Store).RunPassAsync(CancellationToken.None);

        // The deleted org's tenant-scoped audit row is gone; its scope='system' row survives
        // (adversarial twin: the system sweep must not collaterally destroy operator rows).
        Assert.Equal(0, await CountAsync("a-tenant"));
        Assert.Equal(1, await CountAsync("a-system"));

        // A different tenant's audit rows are untouched.
        Assert.Equal(1, await CountAsync("b-tenant"));
    }
}
