using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Personal-data retention sweeps added to the GC pass: audit_log two-horizon
/// (pseudonymize then delete), login_attempts idle prune, trusted-device expiry prune,
/// and the activity NULL-resolves-to-instance-default behaviour. Every assertion selects
/// the rows back from the real store rather than trusting the writer.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionPersonalDataSweepTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
        // o1: activity retention unset (NULL) — must resolve to the 90-day instance default.
        // o2: explicit 10-day window — must be honoured over the default.
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, activity_retention_days) VALUES ('o1', NULL), ('o2', 10)");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        var jwt = new JwtRevocationRepository(_db, time: _clock);
        var invites = new InviteRepository(_db, _clock);
        var samlConfig = new SamlConfigRepository(_db, _clock);
        var trusted = new TrustedDeviceService(_db, _clock, cfg);
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, jwt, invites, samlConfig, trusted, cfg, new AirGapMode(cfg),
            NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock())));
    }

    private static string Iso(DateTimeOffset t) => t.ToUtcIso();

    private async Task InsertActivityAsync(string id, string orgId, DateTimeOffset createdAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO activity (id, org_id, ecosystem, event_type, actor_id, source_ip, created_at)
            VALUES (@id, @orgId, 'npm', 'pull', 'u1', '203.0.113.7', @createdAt)
            """,
            new { id, orgId, createdAt = Iso(createdAt) });
    }

    private async Task InsertAuditAsync(string id, string scope, string orgId, DateTimeOffset createdAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, actor_id, action, detail, source_ip, created_at)
            VALUES (@id, @scope, @orgId, 'u1', 'login', '{"email":"a@b.com"}', '203.0.113.7', @createdAt)
            """,
            new { id, scope, orgId, createdAt = Iso(createdAt) });
    }

    private async Task InsertLoginAttemptAsync(string hash, DateTimeOffset lastAttempt, DateTimeOffset? lockedUntil)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO login_attempts (email_hash, failed_count, locked_until, last_attempt) VALUES (@hash, 3, @locked, @last)",
            new { hash, locked = lockedUntil is null ? null : Iso(lockedUntil.Value), last = Iso(lastAttempt) });
    }

    private async Task InsertDeviceAsync(string id, DateTimeOffset expiresAt)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO mfa_trusted_devices (id, user_id, realm, tenant_id, token_hash, created_at, expires_at)
            VALUES (@id, 'u1', 'tenant', 'o1', @hash, @created, @expires)
            """,
            new { id, hash = "h-" + id, created = Iso(_clock.GetUtcNow()), expires = Iso(expiresAt) });
    }

    private async Task<T?> ScalarAsync<T>(string sql, object p)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<T>(sql, p);
    }

    [Fact]
    public async Task GcPass_PersonalDataSweeps_PruneScrubAndPreserveByAgeAndScope()
    {
        var now = TestTime.KnownNow;

        // Activity: o1 (NULL → 90d default) and o2 (explicit 10d). Offsets stay far from the
        // boundaries so leap-year drift never flips an assertion.
        await InsertActivityAsync("a-o1-old", "o1", now.AddDays(-120));   // > 90d → gone
        await InsertActivityAsync("a-o1-new", "o1", now.AddDays(-10));    // < 90d → kept
        await InsertActivityAsync("a-o2-mid", "o2", now.AddDays(-50));    // > 10d, < 90d → gone (proves 10d, not default)
        await InsertActivityAsync("a-o2-new", "o2", now.AddDays(-5));     // < 10d → kept

        // audit_log two-horizon: delete > 365d, pseudonymize > 90d, keep < 90d — across scopes.
        await InsertAuditAsync("al-del", "tenant", "o1", now.AddDays(-400)); // > 365d → deleted
        await InsertAuditAsync("al-scrub", "tenant", "o1", now.AddDays(-120)); // 90..365d → kept, PII cleared
        await InsertAuditAsync("al-keep", "tenant", "o1", now.AddDays(-10));  // < 90d → untouched
        await InsertAuditAsync("al-sys-del", "system", "o1", now.AddDays(-400)); // storage limit applies to system rows too
        await InsertAuditAsync("al-sys-keep", "system", "o1", now.AddDays(-10));

        // login_attempts: idle-unlocked > 30d gone; idle-recent kept; locked kept even when old.
        await InsertLoginAttemptAsync("la-idle-old", now.AddDays(-60), lockedUntil: null);
        await InsertLoginAttemptAsync("la-idle-new", now.AddDays(-5), lockedUntil: null);
        await InsertLoginAttemptAsync("la-locked-old", now.AddDays(-60), lockedUntil: now.AddDays(1));

        // trusted devices: expired gone, live kept.
        await InsertDeviceAsync("dev-expired", now.AddDays(-1));
        await InsertDeviceAsync("dev-live", now.AddDays(30));

        await Build().RunGcPassAsync(default);

        // --- activity ---
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE id = 'a-o1-old'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE id = 'a-o1-new'", new { }));
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE id = 'a-o2-mid'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE id = 'a-o2-new'", new { }));

        // --- audit_log deletion horizon ---
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE id = 'al-del'", new { }));
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE id = 'al-sys-del'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE id = 'al-sys-keep'", new { }));

        // --- audit_log pseudonymization horizon: row survives, identifiers gone ---
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE id = 'al-scrub'", new { }));
        Assert.Null(await ScalarAsync<string>("SELECT source_ip FROM audit_log WHERE id = 'al-scrub'", new { }));
        Assert.Null(await ScalarAsync<string>("SELECT detail FROM audit_log WHERE id = 'al-scrub'", new { }));

        // In-window row keeps its identifiers.
        Assert.Equal("203.0.113.7", await ScalarAsync<string>("SELECT source_ip FROM audit_log WHERE id = 'al-keep'", new { }));
        Assert.False(string.IsNullOrEmpty(await ScalarAsync<string>("SELECT detail FROM audit_log WHERE id = 'al-keep'", new { })));

        // --- login_attempts ---
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM login_attempts WHERE email_hash = 'la-idle-old'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM login_attempts WHERE email_hash = 'la-idle-new'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM login_attempts WHERE email_hash = 'la-locked-old'", new { }));

        // --- trusted devices ---
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM mfa_trusted_devices WHERE id = 'dev-expired'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM mfa_trusted_devices WHERE id = 'dev-live'", new { }));
    }

    [Fact]
    public async Task GcPass_JudgesMillisecondPrecisionRows_ByExactInstant_NotByTheirWholeSecond()
    {
        // audit_log.created_at and activity.created_at are millisecond-precision text (their sole
        // writers — AuditRepository.WriteAsync / LogActivityAsync — stamp NowMs()). A retention
        // cutoff sharing a row's whole second must be compared at the same precision: '.' (0x2E)
        // collates before 'Z' (0x5A), so a second-precision cutoff sorts as greater than every
        // millisecond row in that second regardless of the row's real sub-second offset — deleting
        // a row that is actually newer than the cutoff instant. Rows are seeded through the real
        // writer path (not hand-built INSERTs) so this pins the writer/reader contract together.
        var now = TestTime.KnownNow;

        var auditDeleteCutoff = now.AddDays(-365); // AUDIT_LOG_RETENTION_DAYS default
        var activityCutoff = now.AddDays(-90);     // instance default for o1 (NULL policy)

        // FakeTimeProvider refuses to go backward, so seed in ascending chronological order,
        // starting from before the earliest (audit_log, 365-day) boundary.
        var writerClock = TestTime.Frozen(auditDeleteCutoff.AddMilliseconds(-500));
        var audit = new AuditRepository(_db, time: writerClock);

        // audit_log delete horizon: 500ms older than the cutoff instant (the previous whole second)
        // must still be deleted — the adversarial twin — while 500ms newer must survive the pass.
        await audit.LogAsync("login.failure", orgId: "o1", actorId: "u1");
        writerClock.SetUtcNow(auditDeleteCutoff.AddMilliseconds(500));
        await audit.LogAsync("login.success", orgId: "o1", actorId: "u1");

        // activity retention horizon: same shape, against the activity table.
        writerClock.SetUtcNow(activityCutoff.AddMilliseconds(-500));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/out-of-window@1.0.0", "pull", actorId: "u1");
        writerClock.SetUtcNow(activityCutoff.AddMilliseconds(500));
        await audit.LogActivityAsync("o1", "npm", "pkg:npm/in-window@1.0.0", "pull", actorId: "u1");

        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE action = 'login.success'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE action = 'login.failure'", new { }));
        Assert.Equal(2, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE ecosystem = 'npm' AND actor_id = 'u1'", new { }));

        await Build().RunGcPassAsync(default);

        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE action = 'login.success'", new { }));
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM audit_log WHERE action = 'login.failure'", new { }));
        Assert.Equal(1, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE purl = 'pkg:npm/in-window@1.0.0'", new { }));
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM activity WHERE purl = 'pkg:npm/out-of-window@1.0.0'", new { }));
    }
}
