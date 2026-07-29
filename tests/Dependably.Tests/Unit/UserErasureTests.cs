using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// RemoveOrgMemberAsync is a full account erasure. These tests prove the two halves of the
/// defect it fixes: (A) deleting a user who touched any of the seven restrict-FK tables must
/// not throw (the offboarding 500), and (B) the personal data that used to survive — trusted
/// devices, login_attempts/account_send_throttle, IPs in activity/audit — is actually gone.
///
/// <para>
/// login_attempts and account_send_throttle are keyed by <c>LoginService.HashLockoutKey</c>
/// over (realm, tenantId, email), not by userId, and not by a bare email hash. Every row this
/// file seeds into either table is written through the REAL production path — the actual
/// <see cref="SqliteLockoutStore"/> / <see cref="AccountSendThrottle"/> classes keyed by the
/// actual <see cref="LoginService.HashLockoutKey"/> — never a hash recomputed by hand in the
/// test. That is deliberate: a hand-rolled formula in the test would drift in lockstep with a
/// bug in the erasure path's own (formerly wrong) hash and mask the exact defect this suite
/// exists to catch.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class UserErasureTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private string _u1 = "";
    private string _u2 = "";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o1')");
        _u1 = await UserSeeder.InsertAsync(_db, "o1", "u1@acme.test", role: "admin");
        _u2 = await UserSeeder.InsertAsync(_db, "o1", "u2@acme.test", role: "admin");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task<int> CountAsync(string sql, object p)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(sql, p);
    }

    /// <summary>Writes a lockout row through the real store — the same class that serves login.</summary>
    private async Task SeedLockoutAsync(string lockoutKey, int failedCount)
    {
        var lockout = new SqliteLockoutStore(_db, _clock);
        await lockout.RecordFailureAsync(lockoutKey, failedCount, lockedUntil: null, ct: default);
    }

    /// <summary>Writes a send-throttle row through the real class — same pseudonym as login_attempts.</summary>
    private async Task SeedSendThrottleAsync(string lockoutKey)
    {
        var config = new ConfigurationBuilder().Build();
        var throttle = new AccountSendThrottle(_db, _clock, config, NullLogger<AccountSendThrottle>.Instance);
        await throttle.TryConsumeAsync(lockoutKey, AccountSendThrottle.PurposePasswordReset, default);
    }

    // Seeds one row in each of the seven restrict-FK tables attributing to userId, plus a
    // trusted device, and an activity + audit_log row carrying the user's source IP. suffix
    // keeps unique keys distinct per user.
    private async Task SeedUserFootprintAsync(string userId, string suffix)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO invites (id, org_id, email, token_hash, created_by, expires_at) VALUES (@id, 'o1', @invitee, @th, @u, '2999-01-01T00:00:00Z')",
            new { id = "inv-" + suffix, invitee = "invitee-" + suffix + "@x.test", th = "th-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern, created_by) VALUES (@id, 'o1', 'npm', @pat, @u)",
            new { id = "rn-" + suffix, pat = "@scope-" + suffix + "/*", u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO quarantine (id, org_id, ecosystem, purl, gate, state, decided_by) VALUES (@id, 'o1', 'npm', @purl, 'malicious', 'approved', @u)",
            new { id = "q-" + suffix, purl = "pkg:npm/q-" + suffix + "@1.0.0", u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title, state, dismissed_by) VALUES (@id, 'o1', 'vuln_severity', @sr, 'Alert', 'dismissed', @u)",
            new { id = "al-" + suffix, sr = "ref-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO claim (id, org_id, ecosystem, name, state, reason, created_by) VALUES (@id, 'o1', 'npm', @name, 'local_only', 'seed', @u)",
            new { id = "c-" + suffix, name = "claim-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO claim_history (id, org_id, claim_id, ecosystem, name, new_state, reason, actor_id) VALUES (@id, 'o1', @cid, 'npm', @name, 'local_only', 'seed', @u)",
            new { id = "ch-" + suffix, cid = "c-" + suffix, name = "claim-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO install_script_allowlist (id, org_id, ecosystem, name, created_by) VALUES (@id, 'o1', 'npm', @name, @u)",
            new { id = "isa-" + suffix, name = "isa-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO mfa_trusted_devices (id, user_id, realm, tenant_id, token_hash, expires_at) VALUES (@id, @u, 'tenant', 'o1', @th, '2999-01-01T00:00:00Z')",
            new { id = "dev-" + suffix, u = userId, th = "devhash-" + suffix });
        await conn.ExecuteAsync(
            "INSERT INTO activity (id, org_id, ecosystem, event_type, actor_id, source_ip, created_at) VALUES (@id, 'o1', 'npm', 'pull', @u, '203.0.113.9', '2026-06-15T12:00:00Z')",
            new { id = "act-" + suffix, u = userId });
        await conn.ExecuteAsync(
            "INSERT INTO audit_log (id, scope, org_id, actor_id, action, detail, source_ip, created_at) VALUES (@id, 'tenant', 'o1', @u, 'login', '{\"email\":\"x@y.com\"}', '203.0.113.9', '2026-06-15T12:00:00Z')",
            new { id = "aud-" + suffix, u = userId });
    }

    [Fact]
    public async Task RemoveOrgMember_ErasesUser_Without500_AndLeavesOtherUsersIntact()
    {
        await SeedUserFootprintAsync(_u1, "u1");
        await SeedUserFootprintAsync(_u2, "u2");

        var repo = new OrgRepository(_db);
        string keyU1 = LoginService.HashLockoutKey("tenant", "o1", "u1@acme.test");

        // Half A: a user who created an invite (and touched every other restrict-FK table) must
        // erase cleanly. The bare DELETE this replaced threw a foreign-key violation → 500.
        var ex = await Record.ExceptionAsync(() => repo.RemoveOrgMemberAsync("o1", _u1, keyU1));
        Assert.Null(ex);

        // The user row is gone.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM users WHERE id = @u", new { u = _u1 }));

        // invites the user created are gone; attribution columns elsewhere are nulled, not deleted
        // (the record survives, the actor reference does not).
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM invites WHERE created_by = @u", new { u = _u1 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM reserved_namespace WHERE id = 'rn-u1' AND created_by IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM quarantine WHERE id = 'q-u1' AND decided_by IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM alert WHERE id = 'al-u1' AND dismissed_by IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM claim WHERE id = 'c-u1' AND created_by IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM claim_history WHERE id = 'ch-u1' AND actor_id IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM install_script_allowlist WHERE id = 'isa-u1' AND created_by IS NULL", new { }));

        // Half B: the live trusted-device credential is gone; the retained forensic rows have
        // their IP scrubbed. (login_attempts/account_send_throttle erasure is covered by the
        // dedicated lockout tests below — they are keyed by email, not userId, so they need
        // their own footprint.)
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @u", new { u = _u1 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM activity WHERE id = 'act-u1' AND source_ip IS NULL", new { }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE id = 'aud-u1' AND source_ip IS NULL AND detail IS NULL", new { }));

        // Adversarial twin: user 2 and every row attributed to them are entirely untouched.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM users WHERE id = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM invites WHERE created_by = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM reserved_namespace WHERE id = 'rn-u2' AND created_by = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM quarantine WHERE id = 'q-u2' AND decided_by = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM claim_history WHERE id = 'ch-u2' AND actor_id = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM mfa_trusted_devices WHERE user_id = @u", new { u = _u2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM activity WHERE id = 'act-u2' AND source_ip = '203.0.113.9'", new { }));
    }

    [Fact]
    public async Task RemoveOrgMember_ClearsTheRealLockoutAndSendThrottleRows_WrittenByTheActualStores()
    {
        // The row is written by the real SqliteLockoutStore/AccountSendThrottle classes, keyed by
        // the real LoginService.HashLockoutKey — not a hash reimplemented in this test. If the
        // erasure path's own key computation ever diverges from these again, this row simply
        // survives the deletion.
        string keyU1 = LoginService.HashLockoutKey("tenant", "o1", "u1@acme.test");
        await SeedLockoutAsync(keyU1, failedCount: 3);
        await SeedSendThrottleAsync(keyU1);

        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = keyU1 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = keyU1 }));

        var repo = new OrgRepository(_db);
        await repo.RemoveOrgMemberAsync("o1", _u1, keyU1);

        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = keyU1 }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = keyU1 }));
    }

    [Fact]
    public async Task RemoveOrgMember_DoesNotClearAnotherUsersLockoutRow_IncludingSameEmailInADifferentTenant()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'other')");
            await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o2')");
        }
        // A third user, in a DIFFERENT tenant, at the EXACT SAME address as u1. A naive fix keyed
        // on the bare email (rather than the tenant-scoped LoginService.HashLockoutKey) would
        // erase this row too when u1 is removed from o1 — that is precisely the cross-tenant
        // leak this test exists to catch.
        string u3 = await UserSeeder.InsertAsync(_db, "o2", "u1@acme.test", role: "admin");

        string keyU1O1 = LoginService.HashLockoutKey("tenant", "o1", "u1@acme.test");
        string keyU2O1 = LoginService.HashLockoutKey("tenant", "o1", "u2@acme.test");
        string keyU1O2 = LoginService.HashLockoutKey("tenant", "o2", "u1@acme.test");

        // Three distinct rows: same tenant/different email, same email/different tenant, and the
        // subject itself.
        await SeedLockoutAsync(keyU1O1, failedCount: 3);
        await SeedLockoutAsync(keyU2O1, failedCount: 4);
        await SeedLockoutAsync(keyU1O2, failedCount: 5);
        await SeedSendThrottleAsync(keyU1O1);
        await SeedSendThrottleAsync(keyU2O1);
        await SeedSendThrottleAsync(keyU1O2);

        var repo = new OrgRepository(_db);
        await repo.RemoveOrgMemberAsync("o1", _u1, keyU1O1);

        // The subject's own row is gone.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = keyU1O1 }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = keyU1O1 }));

        // A different user in the same tenant keeps their row.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = keyU2O1 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = keyU2O1 }));

        // The same email address in a different tenant keeps its row too — the erasure of one
        // tenant's account must never reach into another tenant's lockout state.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM login_attempts WHERE email_hash = @k", new { k = keyU1O2 }));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM account_send_throttle WHERE email_hash = @k", new { k = keyU1O2 }));

        // And the other tenant's user row itself was never touched by o1's erasure.
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM users WHERE id = @u", new { u = u3 }));
    }
}
