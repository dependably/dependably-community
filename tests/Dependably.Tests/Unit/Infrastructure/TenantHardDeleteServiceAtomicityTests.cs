using Dapper;
using Dependably.Background;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The per-tenant hard-delete sequence spans six relations, and only one of them — the
/// <c>orgs</c> row — is visible to the query that builds the next pass's worklist
/// (<see cref="OrgRepository.ListExpiredSoftDeletedOrgIdsAsync"/>, a SELECT over <c>orgs</c>).
/// So a sequence that commits the <c>orgs</c> DELETE and then fails is not retryable in any
/// sense: the id can never be listed again, and the banners, lockout/send-throttle pseudonyms,
/// tenant-scoped <c>audit_log</c> rows and un-pseudonymized <c>audit_event</c> identifiers it
/// left behind are stranded permanently — which is exactly the Art. 17 personal data the sweep
/// exists to erase.
///
/// These tests inject a mid-sequence failure (a trigger that aborts the tenant <c>audit_log</c>
/// DELETE, standing in for the SQLITE_BUSY-under-write-contention case the sweep's per-tenant
/// catch is written for) and assert the sweep's own claim: that the next pass retries the
/// tenant and finishes the erasure.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TenantHardDeleteServiceAtomicityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TenantHardDeleteServiceAtomicityTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);

    // audit_log.detail value that arms the failure trigger below. Matching on a column value
    // rather than on the org id keeps the trigger DDL a constant while still letting one tenant
    // in a multi-tenant pass fail while the others succeed.
    private const string AbortSentinel = "hd-abort-sentinel";

    private static TenantHardDeleteService BuildService(IMetadataStore db, TimeProvider clock)
    {
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
            new InProcessDistributedLock(clock),
            NullLogger<TenantHardDeleteService>.Instance,
            clock);
    }

    // Aborts any DELETE of an audit_log row carrying the sentinel detail — a database-side stand-in
    // for the transient write failure (SQLITE_BUSY, lock timeout) that the sweep's per-tenant catch
    // swallows. Armed for one pass, then dropped to model the condition clearing.
    private async Task ArmAuditDeleteFailureAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            CREATE TRIGGER hd_abort_audit_delete BEFORE DELETE ON audit_log
            WHEN OLD.detail = 'hd-abort-sentinel'
            BEGIN SELECT RAISE(ABORT, 'simulated transient write failure on audit_log'); END
            """);
    }

    private async Task DisarmAuditDeleteFailureAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("DROP TRIGGER hd_abort_audit_delete");
    }

    private async Task<int> CountAsync(string sql, object p)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(sql, p);
    }

    private async Task ExpireAsync(string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE orgs SET deleted_at = @dt WHERE id = @id",
            new { dt = KnownNow.AddDays(-60).ToUtcIso(), id = orgId });
    }

    private async Task SeedTenantAuditAsync(string id, string orgId, string detail)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, action, detail, source_ip)
            VALUES (@id, 'tenant', @orgId, 'actor', 'login.failure', @detail, '203.0.113.4')
            """,
            new { id, orgId, detail });
    }

    private async Task SeedAuditEventAsync(string eventId, string orgId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_event (
                event_id, schema_version, event_type, org_id, tenant_resolver,
                actor_type, actor_id, source_ip, user_agent, outcome, payload, occurred_at)
            VALUES (
                @eventId, 1, 'test.event', @orgId, 'single',
                'user', 'actor', '203.0.113.4', 'TestAgent/1.0', 'accepted', '{"k":"v"}',
                '2026-01-01T00:00:00.000Z')
            """,
            new { eventId, orgId });
    }

    private async Task<string?> ReadAuditEventSourceIpAsync(string eventId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT source_ip FROM audit_event WHERE event_id = @eventId", new { eventId });
    }

    // Seeds the full non-cascading personal-data set for one tenant and returns the member's
    // lockout pseudonym, computed through the real LoginService.HashLockoutKey.
    private async Task<string> SeedTenantPersonalDataAsync(
        FakeTimeProvider clock, string orgId, string email, string auditId, string eventId, string auditDetail)
    {
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email);
        string lockoutKey = LoginService.HashLockoutKey("tenant", orgId, email);
        // The store owns the increment, so a count is seeded by recording that many failures.
        // maxFailedAttempts is int.MaxValue so seeding never trips the lockout: this test cares
        // that a login_attempts row exists and is erased, not what its failed_count holds.
        var lockout = new SqliteLockoutStore(_fixture.Store, clock);
        for (int i = 0; i < 3; i++)
        {
            await lockout.RecordFailureAsync(
                lockoutKey, maxFailedAttempts: int.MaxValue, TimeSpan.FromMinutes(15), ct: default);
        }
        await new AccountSendThrottle(
                _fixture.Store, clock, new ConfigurationBuilder().Build(),
                NullLogger<AccountSendThrottle>.Instance)
            .TryConsumeAsync(lockoutKey, AccountSendThrottle.PurposePasswordReset, default);
        await SeedTenantAuditAsync(auditId, orgId, auditDetail);
        await SeedAuditEventAsync(eventId, orgId);
        return lockoutKey;
    }

    /// <summary>
    /// A failure partway through one tenant's erasure must leave that tenant exactly as it was —
    /// still soft-deleted, still past grace, still in the next pass's worklist — and the next pass
    /// must finish the job. Without the transaction the <c>orgs</c> DELETE has already committed by
    /// the time the <c>audit_log</c> DELETE fails, so the second pass's worklist query finds
    /// nothing and every stranded personal-data row survives forever.
    /// </summary>
    [Fact]
    public async Task RunPassAsync_FailureMidErasure_LeavesTenantRetryable_AndTheNextPassErasesEverything()
    {
        var clock = TestTime.Frozen(KnownNow);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-atomic-{Guid.NewGuid():N}");
        string lockoutKey = await SeedTenantPersonalDataAsync(
            clock, orgId, "member@atomic.test", "atomic-audit", "atomic-event", AbortSentinel);

        var bannerRepo = new BannerRepository(_fixture.Store, clock);
        string bannerAuthor = await UserSeeder.InsertAsync(_fixture.Store, orgId, "author@atomic.test");
        var banner = await bannerRepo.CreateTenantAsync(
            orgId, bannerAuthor,
            new BannerCreateRequest(
                "info", "Test body", null, null, "all",
                KnownNow.AddDays(-1).ToUtcIso(), KnownNow.AddDays(30).ToUtcIso(), true),
            CancellationToken.None);

        await ExpireAsync(orgId);

        var svc = BuildService(_fixture.Store, clock);

        // Pass 1: the audit_log DELETE fails partway through the erasure. The sweep swallows it.
        await ArmAuditDeleteFailureAsync();
        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);

        // The tenant is still on the worklist, so "the next pass retries this tenant" is true.
        // Once the orgs row is gone this query — the sweep's only source of work — can never
        // name the id again, and everything below is stranded for good.
        var expiredAfterFailure = await new OrgRepository(_fixture.Store, null, clock)
            .ListExpiredSoftDeletedOrgIdsAsync(0, CancellationToken.None);
        Assert.Contains(orgId, expiredAfterFailure);

        // Nothing was half-erased: the tenant is intact.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM banners WHERE id = @id", new { id = banner.Id }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = lockoutKey }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE id = 'atomic-audit'", new { }));
        Assert.Equal(
            0,
            await CountAsync(
                "SELECT COUNT(*) FROM audit_log WHERE org_id = @id AND action = 'tenant.hard_deleted'",
                new { id = orgId }));

        // Pass 2, with the transient condition cleared: the retry completes the whole erasure.
        await DisarmAuditDeleteFailureAsync();
        await svc.RunPassAsync(CancellationToken.None);

        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = orgId }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM banners WHERE id = @id", new { id = banner.Id }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = lockoutKey }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = lockoutKey }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE id = 'atomic-audit'", new { }));
        Assert.Null(await ReadAuditEventSourceIpAsync("atomic-event"));

        // Exactly one operator lifecycle row: the failed pass wrote none, the retry wrote one.
        Assert.Equal(
            1,
            await CountAsync(
                "SELECT COUNT(*) FROM audit_log WHERE org_id = @id AND action = 'tenant.hard_deleted'",
                new { id = orgId }));
    }

    /// <summary>
    /// Mixed partial failure within one pass: one tenant's erasure fails mid-sequence while another
    /// tenant's succeeds. The failing tenant must roll back whole (and stay retryable), and the
    /// succeeding tenant must still be erased completely — the per-tenant transaction must not be
    /// a batch-wide one.
    /// </summary>
    [Fact]
    public async Task RunPassAsync_OneTenantFailsMidErasure_OtherTenantInSamePassIsStillFullyErased()
    {
        var clock = TestTime.Frozen(KnownNow);
        string failingOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-mixed-fail-{Guid.NewGuid():N}");
        string healthyOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"hd-mixed-ok-{Guid.NewGuid():N}");

        string failingKey = await SeedTenantPersonalDataAsync(
            clock, failingOrg, "member@fail.test", "mixed-fail-audit", "mixed-fail-event", AbortSentinel);
        string healthyKey = await SeedTenantPersonalDataAsync(
            clock, healthyOrg, "member@ok.test", "mixed-ok-audit", "mixed-ok-event", "ordinary detail");

        await ExpireAsync(failingOrg);
        await ExpireAsync(healthyOrg);

        await ArmAuditDeleteFailureAsync();
        var svc = BuildService(_fixture.Store, clock);
        var ex = await Record.ExceptionAsync(() => svc.RunPassAsync(CancellationToken.None));
        Assert.Null(ex);
        await DisarmAuditDeleteFailureAsync();

        // The healthy tenant is fully erased despite its neighbour failing.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = healthyOrg }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE id = 'mixed-ok-audit'", new { }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = healthyKey }));
        Assert.Null(await ReadAuditEventSourceIpAsync("mixed-ok-event"));

        // The failing tenant is untouched — no partial erasure, and still on the worklist.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM orgs WHERE id = @id", new { id = failingOrg }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE id = 'mixed-fail-audit'", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = failingKey }));
        Assert.Equal("203.0.113.4", await ReadAuditEventSourceIpAsync("mixed-fail-event"));

        var stillExpired = await new OrgRepository(_fixture.Store, null, clock)
            .ListExpiredSoftDeletedOrgIdsAsync(0, CancellationToken.None);
        Assert.Contains(failingOrg, stillExpired);
        Assert.DoesNotContain(healthyOrg, stillExpired);
    }
}
