using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the <c>lowercase_nuget_hosted_versions</c> one-shot migration. A package
/// holding two non-lowercase casings of the same version (creatable on the pre-fix code, whose
/// duplicate-version check compared case-preserved strings against the BINARY-collated column)
/// makes the naive migration attempt to lowercase both rows to the same value in one UPDATE —
/// the WHERE clause evaluates against the pre-update snapshot, so both rows' collision guards
/// pass simultaneously and the second write hits UNIQUE(package_id, version). Because
/// RunOnceAsync wraps the migration in a transaction, the failure rolls back the whole
/// statement and the migration is never recorded in <c>_applied_migrations</c> — every
/// subsequent boot retries and fails identically (a permanent boot loop).
///
/// The fix adds a deterministic single-winner tiebreaker (smallest id) so at most one row per
/// colliding group is ever updated; the rest are left mixed-case (unreachable, but no worse
/// than before the fix) instead of crashing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LowercaseNuGetHostedVersionsMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private const string MigrationName = "lowercase_nuget_hosted_versions";

    private static async Task<string> SeedPackageAsync(DbConnection conn, string orgId, string purlName)
    {
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = orgId, slug = orgId });
        string packageId = "pkg-" + purlName;
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES (@id, @orgId, 'nuget', @name, @purlName, 0)",
            new { id = packageId, orgId, name = purlName, purlName });
        return packageId;
    }

    private static Task<int> SeedVersionAsync(
        DbConnection conn, string versionId, string packageId, string version, string blobKey)
        => conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) " +
            "VALUES (@id, @packageId, @version, @purl, @blobKey)",
            new { id = versionId, packageId, version, purl = $"pkg:nuget/{packageId}@{version}", blobKey });

    private static Task<int> RearmMigrationAsync(DbConnection conn) =>
        conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = @name", new { name = MigrationName });

    private static async Task<bool> IsMigrationRecordedAsync(DbConnection conn) =>
        await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @name", new { name = MigrationName }) > 0;

    [Fact]
    public async Task TwoMixedCaseRows_NoExistingLowercaseTwin_MigratesExactlyOneWinner_NoUniqueViolation()
    {
        // Pathological pair B: "Beta1" + "BETA1", neither already lowercase. This is the
        // scenario that crashes the un-fixed migration — both rows' NOT EXISTS guard passes
        // simultaneously since neither "1.0.0-beta1" row exists yet.
        const string orgId = "org-nuget-collide-both-mixed";
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            string packageId = await SeedPackageAsync(setup, orgId, "collide.bothmixed");
            await SeedVersionAsync(setup, "v-beta1", packageId, "1.0.0-Beta1", "hosted/collide.bothmixed.1.0.0-beta1.nupkg");
            await SeedVersionAsync(setup, "v-BETA1", packageId, "1.0.0-BETA1", "hosted/collide.bothmixed.1.0.0-beta1-b.nupkg");
            await RearmMigrationAsync(setup);
        }

        // Must not throw a UNIQUE violation despite the collision.
        var ex = await Record.ExceptionAsync(() => new SchemaInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();

        // The migration must record itself as applied — a thrown/rolled-back UPDATE would leave
        // this false and cause every subsequent boot to retry and fail identically.
        Assert.True(await IsMigrationRecordedAsync(verify));

        // Exactly one row at the lowercased coordinate must exist (no UNIQUE violation, no
        // duplicate lowercase rows).
        long lowerCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE version = '1.0.0-beta1'");
        Assert.Equal(1, lowerCount);

        // The other row stays at its original mixed case (acceptable residue — unreachable,
        // but not a crash). Confirm exactly one of the two original rows was touched.
        string? beta1Version = await verify.ExecuteScalarAsync<string?>(
            "SELECT version FROM package_versions WHERE id = 'v-beta1'");
        string? betaCapsVersion = await verify.ExecuteScalarAsync<string?>(
            "SELECT version FROM package_versions WHERE id = 'v-BETA1'");
        string?[] survivingVersions = new[] { beta1Version, betaCapsVersion };
        Assert.Single(survivingVersions, v => v == "1.0.0-beta1");
        Assert.Single(survivingVersions, v => v != "1.0.0-beta1");
    }

    [Fact]
    public async Task MixedCaseRowWithExistingLowercaseTwin_SkipsMixedRow_NoUniqueViolation()
    {
        // Pathological pair A: "Beta1" alongside an already-canonical "beta1". The original
        // NOT EXISTS guard already covers this pair correctly (it is not the crashing case),
        // but it is included as a fixed regression pin per the acceptable-residue contract:
        // the mixed-case row must be silently skipped, not migrated over the existing row.
        const string orgId = "org-nuget-collide-one-lower";
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            string packageId = await SeedPackageAsync(setup, orgId, "collide.onelower");
            await SeedVersionAsync(setup, "v-beta1-lower", packageId, "1.0.0-beta1", "hosted/collide.onelower.1.0.0-beta1.nupkg");
            await SeedVersionAsync(setup, "v-Beta1-mixed", packageId, "1.0.0-Beta1", "hosted/collide.onelower.1.0.0-beta1-b.nupkg");
            await RearmMigrationAsync(setup);
        }

        var ex = await Record.ExceptionAsync(() => new SchemaInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        Assert.True(await IsMigrationRecordedAsync(verify));

        // Exactly one downloadable lowercase row.
        long lowerCount = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE version = '1.0.0-beta1'");
        Assert.Equal(1, lowerCount);

        // The pre-existing lowercase row is untouched and the mixed-case row is left alone
        // (skipped by the NOT EXISTS guard) rather than colliding with it.
        string? lowerRowVersion = await verify.ExecuteScalarAsync<string?>(
            "SELECT version FROM package_versions WHERE id = 'v-beta1-lower'");
        Assert.Equal("1.0.0-beta1", lowerRowVersion);
        string? mixedRowVersion = await verify.ExecuteScalarAsync<string?>(
            "SELECT version FROM package_versions WHERE id = 'v-Beta1-mixed'");
        Assert.Equal("1.0.0-Beta1", mixedRowVersion);
    }
}
