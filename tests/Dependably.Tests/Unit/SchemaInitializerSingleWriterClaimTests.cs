using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Where the SQLite single-writer claim sits inside the schema apply. It cannot be taken before
/// the base schema runs — <c>instance_lock</c> is one of the tables that pass creates — but it
/// must be taken before the one-time migrations, which are non-idempotent, partly unwrapped by
/// transaction, and on a large database the longest stretch of startup. Claimed after the apply
/// instead, two processes sharing one database file both run that sequence, and
/// <c>SchemaInitializer.MigrationLock</c>'s stated reason for having no SQLite arm — that
/// <see cref="InstanceLock"/> already refuses a second process — would not hold when it matters.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaInitializerSingleWriterClaimTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Claim_IsTaken_AfterTheBaseSchema_ButBeforeAnyOneTimeMigration()
    {
        long ledgeredAtClaim = -1;
        bool instanceLockTableExisted = false;
        bool lateMigrationAlreadyRun = true;

        await new SchemaInitializer(_db).InitializeAsync(async ct =>
        {
            await using var probe = await _db.OpenAsync(ct);

            // The table the guard lives in exists by now, so the claim can actually be made.
            instanceLockTableExisted = await probe.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'instance_lock'") == 1;

            ledgeredAtClaim = await probe.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM _applied_migrations");

            // A migration from deep in the sequence, named directly rather than counted, so the
            // assertion says "the sequence has not started" rather than "some number is smaller".
            lateMigrationAlreadyRun = await probe.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'expand_alert_type_check_vuln_kev'") > 0;
        });

        Assert.True(instanceLockTableExisted, "instance_lock must exist before the claim is attempted");

        await using var verify = await _db.OpenAsync();
        long ledgeredAtEnd = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations");

        // A fresh database ledgers a long sequence of one-time migrations during the apply. All but
        // the two pre-base table renames must still be ahead of the claim, so this is a wide gap
        // rather than an off-by-one: the assertion fails outright if the claim is moved to after
        // the apply, where the two counts would be equal.
        Assert.True(
            ledgeredAtClaim < ledgeredAtEnd,
            $"claim ran after the migration sequence: {ledgeredAtClaim} ledgered at claim, {ledgeredAtEnd} at end");
        Assert.False(lateMigrationAlreadyRun, "the migration sequence had already started at claim time");
        Assert.Equal(1, await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = 'expand_alert_type_check_vuln_kev'"));
    }

    /// <summary>
    /// The hook is optional, so every other caller of <c>InitializeAsync</c> — the test suite and
    /// the SQLite-to-Postgres migration tool — keeps applying the schema with no claim at all.
    /// </summary>
    [Fact]
    public async Task Apply_WithNoClaimHook_StillSucceeds()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        Assert.True(await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations") > 0);
    }
}
