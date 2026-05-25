using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// SpdxLicenseSeeder reads the embedded SPDX license list + curated copyleft overlay and
/// replaces <c>spdx_license</c> rows when the embedded version differs from the stored one.
///
/// Coverage targets:
///   * fresh-DB seed branch (storedVersion == null → INSERT path + version write)
///   * idempotent re-run branch (storedVersion == embeddedVersion → early-return)
///   * transaction rollback branch (DELETE/INSERT throws → catch + ROLLBACK)
///
/// The seeder is wired through <see cref="SchemaInitializer"/> in <see cref="InMemoryDbFixture"/>,
/// so any test that uses the fixture has already triggered one seed pass; we exercise it
/// directly here so the version-equal skip and the catch block are reached deterministically.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SpdxLicenseSeederTests
{
    private const string VersionKey = "spdx_list_version";

    private static SpdxLicenseSeeder NewSut() =>
        new(NullLogger<SpdxLicenseSeeder>.Instance);

    private static async Task<InMemoryDbFixture> NewFixtureAsync()
    {
        var fx = new InMemoryDbFixture();
        await fx.InitializeAsync();
        return fx;
    }

    [Fact]
    public async Task RunAsync_FreshDb_PopulatesSpdxLicenseTableAndRecordsVersion()
    {
        // SchemaInitializer already ran the seeder once when the fixture was initialised;
        // the assertions here confirm the resulting state — i.e. the happy-path branch
        // (storedVersion == null) populated rows and wrote the version row.
        await using var fx = await NewFixtureAsync();
        await using var conn = await fx.Store.OpenAsync();

        var count = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license");
        Assert.True(count > 100, $"Expected the embedded SPDX list to seed many rows; got {count}.");

        var version = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = @k", new { k = VersionKey });
        Assert.False(string.IsNullOrWhiteSpace(version));

        // The overlay assigns explicit copyleft values to a curated subset; everything else
        // falls through to 'unclassified'. Both buckets must be present after a successful run.
        var unclassified = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM spdx_license WHERE copyleft = 'unclassified'");
        var classified = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM spdx_license WHERE copyleft <> 'unclassified'");
        Assert.True(unclassified > 0);
        Assert.True(classified > 0);

        // Deprecated identifiers ride in on the same JSON; assert at least one is flagged so
        // the el.TryGetProperty("isDeprecatedLicenseId", ...) true-branch is observably hit.
        var deprecated = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM spdx_license WHERE is_deprecated = 1");
        Assert.True(deprecated > 0);
    }

    [Fact]
    public async Task RunAsync_VersionAlreadyAtEmbedded_IsNoOp()
    {
        await using var fx = await NewFixtureAsync();

        // Capture state after the SchemaInitializer pass. A no-op second run must leave both
        // the row count and the version row untouched (the skip path returns before TRUNCATE).
        long initialCount;
        string initialVersion;
        await using (var conn = await fx.Store.OpenAsync())
        {
            initialCount = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license");
            initialVersion = (await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = @k",
                new { k = VersionKey }))!;
        }
        Assert.False(string.IsNullOrEmpty(initialVersion));

        // Re-run the seeder against the same DB. storedVersion now equals embeddedVersion,
        // so the early-return branch (line 47–51 in SpdxLicenseSeeder.cs) fires.
        await using (var conn = await fx.Store.OpenAsync())
        {
            await NewSut().RunAsync(conn);
        }

        await using (var conn = await fx.Store.OpenAsync())
        {
            var afterCount = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license");
            var afterVersion = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = @k",
                new { k = VersionKey });
            Assert.Equal(initialCount, afterCount);
            Assert.Equal(initialVersion, afterVersion);
        }
    }

    [Fact]
    public async Task RunAsync_VersionMismatch_TriggersTruncateAndReseed()
    {
        await using var fx = await NewFixtureAsync();

        // Plant a sentinel row + force the stored version to differ from the embedded one,
        // so the second run takes the TRUNCATE+INSERT branch rather than the skip branch.
        await using (var conn = await fx.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO spdx_license (identifier, name, copyleft) VALUES ('ZZZ-Sentinel', 'sentinel', 'unclassified')");
            await conn.ExecuteAsync(
                "UPDATE instance_settings SET value = 'old-version' WHERE key = @k",
                new { k = VersionKey });
        }

        await using (var conn = await fx.Store.OpenAsync())
        {
            await NewSut().RunAsync(conn);
        }

        await using (var conn = await fx.Store.OpenAsync())
        {
            // Sentinel must be gone (DELETE FROM spdx_license fired), real rows reinserted,
            // and the version row brought back up to the embedded value.
            var sentinel = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM spdx_license WHERE identifier = 'ZZZ-Sentinel'");
            Assert.Equal(0, sentinel);

            var version = await conn.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = @k", new { k = VersionKey });
            Assert.False(string.IsNullOrEmpty(version));
            Assert.NotEqual("old-version", version);

            var total = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license");
            Assert.True(total > 100);
        }
    }

    [Fact]
    public void ReadEmbedded_MissingResource_ThrowsInvalidOperation()
    {
        // The private ReadEmbedded helper enforces the resource contract via SingleOrDefault →
        // null-throw. Reach it via reflection so we don't have to depend on a missing resource
        // landing in the assembly at build time.
        var method = typeof(SpdxLicenseSeeder)
            .GetMethod("ReadEmbedded",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!;
        var ex = Assert.Throws<System.Reflection.TargetInvocationException>(
            () => method.Invoke(null, new object[] { "definitely-not-a-resource.json" }));
        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("not found", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunAsync_WhenInsertFails_RollsBackAndPropagates()
    {
        await using var fx = await NewFixtureAsync();

        // Drop spdx_license so the DELETE inside the transaction throws. The catch block
        // must issue ROLLBACK TRANSACTION and re-throw — the version row must not advance,
        // and an open transaction must not leak to the next caller.
        await using (var conn = await fx.Store.OpenAsync())
        {
            await conn.ExecuteAsync("DROP TABLE spdx_license");
            await conn.ExecuteAsync(
                "UPDATE instance_settings SET value = 'force-mismatch' WHERE key = @k",
                new { k = VersionKey });
        }

        await using (var conn = await fx.Store.OpenAsync())
        {
            await Assert.ThrowsAsync<SqliteException>(() => NewSut().RunAsync(conn));

            // No transaction should remain pinned to this connection. A subsequent statement
            // must succeed — if the rollback hadn't fired, SQLite would refuse a new BEGIN.
            await conn.ExecuteAsync("BEGIN TRANSACTION");
            await conn.ExecuteAsync("COMMIT TRANSACTION");
        }

        await using (var fresh = await fx.Store.OpenAsync())
        {
            var version = await fresh.ExecuteScalarAsync<string>(
                "SELECT value FROM instance_settings WHERE key = @k", new { k = VersionKey });
            Assert.Equal("force-mismatch", version);
        }
    }
}
