using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Dependably.Tests.Unit.Infrastructure;
using Npgsql;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres race between a credential mint and a tenant suspension. A mint that read the
/// tenant as active before the suspension began must not commit its credential after the
/// suspension's revoke: the mint's <see cref="TenantMintGate"/> read locks the org row
/// <c>FOR SHARE</c>, so it either waits for the suspension and refuses, or commits first and is
/// revoked by the suspension that was waiting behind it.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class TenantMintPostgresRaceTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    public static TheoryData<string> MintNames() => TenantMintGateTests.MintNames();

    [Theory]
    [MemberData(nameof(MintNames))]
    public async Task MintRacingAnUncommittedSuspension_WaitsForIt_ThenRefuses(string name)
    {
        var mint = TenantMintGateTests.Mints.Single(m => m.Name == name);
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-mint-race");
        string userId = await UserSeeder.InsertAsync(store, orgId, "mint@x.test", role: "admin");
        var tenant = new TenantMintGateTests.Tenant(orgId, userId);

        // The suspension: status written and the org row locked, not yet committed.
        await using var suspender = new NpgsqlConnection(ConnectionString);
        await suspender.OpenAsync();
        await using var suspension = await suspender.BeginTransactionAsync();
        await suspender.ExecuteAsync(
            "UPDATE orgs SET status = 'suspended' WHERE id = @orgId", new { orgId }, suspension);

        var minting = mint.Run(store, tenant);
        await WaitUntilABackendIsBlockedOnALockAsync("SELECT status FROM orgs%FOR SHARE");
        Assert.False(minting.IsCompleted, "the mint must wait for the uncommitted suspension");

        await suspension.CommitAsync();
        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => minting);
        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);

        await using var conn = await store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(mint.CountSql, new { orgId }));
    }

    public static TheoryData<string> RedemptionNames() => TenantRedemptionGateTests.RedemptionNames();

    /// <summary>
    /// The redemption twin of the mint race: an invite or link minted while the tenant was active,
    /// redeemed while a suspension holds the org row. The redemption must wait for the suspension,
    /// then refuse without consuming the credential, so nothing it would have written exists for
    /// the restore to bring back.
    /// </summary>
    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task RedemptionRacingAnUncommittedSuspension_WaitsForIt_ThenRefuses_AndConsumesNothing(string name)
    {
        var redemption = TenantRedemptionGateTests.Redemptions.Single(r => r.Name == name);
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-redeem-race");
        string userId = await UserSeeder.InsertAsync(store, orgId, "redeem@x.test", role: "admin");
        string raw = await redemption.Mint(store, new TenantRedemptionGateTests.Tenant(orgId, userId));

        await using var suspender = new NpgsqlConnection(ConnectionString);
        await suspender.OpenAsync();
        await using var suspension = await suspender.BeginTransactionAsync();
        await suspender.ExecuteAsync(
            "UPDATE orgs SET status = 'suspended' WHERE id = @orgId", new { orgId }, suspension);

        var redeeming = redemption.Redeem(store, raw);
        await WaitUntilABackendIsBlockedOnALockAsync("SELECT status FROM orgs%FOR SHARE");
        Assert.False(redeeming.IsCompleted, "the redemption must wait for the uncommitted suspension");

        await suspension.CommitAsync();
        var ex = await Assert.ThrowsAsync<TenantNotReadyException>(() => redeeming);
        Assert.Equal(TenantNotReadyReason.StatusInactive, ex.Reason);

        await using var conn = await store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(redemption.PendingSql, new { OrgId = orgId }));
    }

    /// <summary>
    /// Active twin on the same live database: with no suspension holding the org row, the same
    /// redemption commits and consumes its credential, so the refusal above is the suspension's doing.
    /// </summary>
    [Theory]
    [MemberData(nameof(RedemptionNames))]
    public async Task RedemptionOnAnActiveTenant_Commits(string name)
    {
        var redemption = TenantRedemptionGateTests.Redemptions.Single(r => r.Name == name);
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-redeem-active");
        string userId = await UserSeeder.InsertAsync(store, orgId, "active@x.test", role: "admin");
        string raw = await redemption.Mint(store, new TenantRedemptionGateTests.Tenant(orgId, userId));

        Assert.True(await redemption.Redeem(store, raw));

        await using var conn = await store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(redemption.PendingSql, new { OrgId = orgId }));
    }

    /// <summary>
    /// An email-change redemption whose target address is being claimed by an uncommitted
    /// competing account insert. The redemption's collision check cannot see the uncommitted row,
    /// so its UPDATE waits on the unique index and then fails when the competitor commits. That
    /// failure must roll the whole redemption back: the address stays as it was and the link stays
    /// redeemable, so the next attempt sees the claimed address and answers the ordinary conflict.
    /// </summary>
    [Fact]
    public async Task EmailChangeRacingAConcurrentClaimOfTheAddress_RollsBackWhole_AndLeavesTheLinkRedeemable()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-email-race");
        string userId = await UserSeeder.InsertAsync(store, orgId, "mover@x.test", role: "admin");
        var tokens = new EmailChangeTokenRepository(store, TestTime.Frozen());
        string raw = await tokens.IssueAsync(userId, orgId, "contested@x.test");
        var users = new UserService(store, new OrgRepository(store, time: TestTime.Frozen()));

        await using var claimer = new NpgsqlConnection(ConnectionString);
        await claimer.OpenAsync();
        await using var claim = await claimer.BeginTransactionAsync();
        await claimer.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ('claimer', @orgId, 'contested@x.test', '', 'member')",
            new { orgId }, claim);

        var confirming = users.ConfirmEmailChangeAsync(tokens, raw);
        await WaitUntilABackendIsBlockedOnALockAsync("UPDATE users%");
        Assert.False(confirming.IsCompleted, "the address write must wait for the uncommitted claim");

        await claim.CommitAsync();
        var raced = await confirming;

        Assert.NotNull(raced);
        Assert.Null(raced.Token);
        Assert.Null(raced.NewTokenVersion);
        await using (var conn = await store.OpenAsync())
        {
            Assert.Equal("mover@x.test", await conn.ExecuteScalarAsync<string>(
                "SELECT email FROM users WHERE id = @userId", new { userId }));
            Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @userId AND consumed_at IS NULL", new { userId }));
        }

        // The link survived, so a retry redeems it and gets the ordinary conflict, spending it.
        var retry = await users.ConfirmEmailChangeAsync(tokens, raw);
        Assert.NotNull(retry);
        Assert.NotNull(retry.Token);
        Assert.Null(retry.NewTokenVersion);
        await using var after = await store.OpenAsync();
        Assert.Equal(0, await after.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM email_change_tokens WHERE user_id = @userId AND consumed_at IS NULL", new { userId }));
        Assert.Equal("mover@x.test", await after.ExecuteScalarAsync<string>(
            "SELECT email FROM users WHERE id = @userId", new { userId }));
    }

    [Fact]
    public async Task SuspensionRacingAnInFlightMint_WaitsForIt_AndRevokesItsCredential()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-mint-first");
        string userId = await UserSeeder.InsertAsync(store, orgId, "first@x.test", role: "admin");

        // An in-flight mint: it has passed the gate (holding the org row FOR SHARE) and inserted,
        // but not yet committed.
        await using var minter = new NpgsqlConnection(ConnectionString);
        await minter.OpenAsync();
        await using var mintTx = await minter.BeginTransactionAsync();
        await minter.ExecuteScalarAsync<string>(
            "SELECT status FROM orgs WHERE id = @orgId AND deleted_at IS NULL FOR SHARE", new { orgId }, mintTx);
        await minter.ExecuteAsync(
            "INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at) VALUES ('inv-1', @orgId, 'x@x.test', 'member', 'h1', @userId, '2999-01-01T00:00:00Z')",
            new { orgId, userId }, mintTx);

        var suspend = new OrgRepository(store, time: TestTime.Frozen()).UpdateOrgStatusAsync(orgId, "suspended");
        await WaitUntilABackendIsBlockedOnALockAsync("SELECT status FROM orgs%FOR UPDATE");
        Assert.False(suspend.IsCompleted, "the suspension must wait for the in-flight mint");

        await mintTx.CommitAsync();
        Assert.True((await suspend).Applied);

        await using var conn = await store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM invites WHERE org_id = @orgId", new { orgId }));
    }

    private static async Task WaitUntilABackendIsBlockedOnALockAsync(string queryLike)
    {
        await using var probe = new NpgsqlConnection(ConnectionString);
        await probe.OpenAsync();
        for (int i = 0; i < 200; i++)
        {
            long waiting = await probe.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM pg_stat_activity
                WHERE datname = current_database() AND wait_event_type = 'Lock'
                  AND ltrim(query) LIKE @queryLike
                """, new { queryLike });
            if (waiting > 0)
            {
                return;
            }

            // now-ok: polls for a real backend on another connection to block on a row lock.
            await Task.Delay(TimeSpan.FromMilliseconds(50), TimeProvider.System);
        }

        throw new TimeoutException($"no backend running {queryLike} blocked on a lock within 10 s");
    }
}
