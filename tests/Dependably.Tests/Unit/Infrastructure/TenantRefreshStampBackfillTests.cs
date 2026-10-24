using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The tenant refresh-stamp backfill walks <c>tenant_artifact_access</c> in bounded, separately
/// committed batches, because a single UPDATE over a large table outlives the client command timeout
/// and fails every boot after. These pin the three properties that makes it depend on: every eligible
/// row is stamped no matter where the batch boundaries fall, a stamp already present is never
/// overwritten, and a run stopped part-way keeps what it committed, records no ledger row, and is
/// finished by the next boot.
/// </summary>
[Trait("Category", "Schema")]
public sealed class TenantRefreshStampBackfillTests : IAsyncLifetime
{
    internal const string Migration = "backfill_tenant_artifact_access_refresh_checked_at";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Backfill_StampsEveryEligibleRow_AcrossBatchBoundaries()
    {
        await using var conn = await _db.OpenAsync();
        await RefreshStampSeed.SeedAsync(conn);

        int batches = await new SchemaInitializer(_db).BackfillTenantArtifactAccessRefreshCheckedAtAsync(
            conn, new WriteLockBudget(2, 2, 2));

        // Seven rows in batches of two: three full batches and a final one of one row.
        Assert.Equal(4, batches);
        Assert.Equal(RefreshStampSeed.Expected, await RefreshStampSeed.StampsAsync(conn));
    }

    [Fact]
    public async Task Backfill_StoppedPartWay_KeepsCommittedBatches_AndTheNextBootFinishes()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await RefreshStampSeed.SeedAsync(conn);
            await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Migration", new { Migration });

            var initializer = new SchemaInitializer(_db);
            var ex = await Record.ExceptionAsync(() => initializer.RunOnceAsync(
                conn, Migration,
                c => initializer.BackfillTenantArtifactAccessRefreshCheckedAtAsync(
                    c, new WriteLockBudget(2, 2, 2),
                    batch => batch == 2 ? throw new InvalidOperationException("stopped") : Task.CompletedTask),
                transactional: false));
            Assert.IsType<InvalidOperationException>(ex);

            Assert.Equal(0L, await LedgerCountAsync(conn));

            // The first two batches (four keys in primary-key order) committed; the rest did not run.
            var stamps = await RefreshStampSeed.StampsAsync(conn);
            var committed = RefreshStampSeed.Expected.Take(4).ToList();
            Assert.Equal(committed, stamps.Take(4).ToList());
            Assert.Equal(
                RefreshStampSeed.Seeded.Skip(4).ToList(),
                stamps.Skip(4).ToList());
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(1L, await LedgerCountAsync(conn));
            Assert.Equal(RefreshStampSeed.Expected, await RefreshStampSeed.StampsAsync(conn));
        }
    }

    /// <summary>
    /// The registered migration itself, driven through <c>InitializeAsync</c> rather than a hand-built
    /// <c>RunOnceAsync</c> call, so the production registration is what is pinned: it must walk the
    /// table in more than one batch, commit each batch on its own (a run stopped part-way keeps
    /// them, which an enclosing transaction would roll back), and record the ledger only once the
    /// walk completes.
    /// </summary>
    [Fact]
    public async Task RegisteredMigration_BatchesCommitsEachBatch_AndRecordsTheLedgerOnlyOnCompletion()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await RefreshStampSeed.SeedAsync(conn);
            await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @Migration", new { Migration });
        }

        var stopping = new SchemaInitializer(_db)
        {
            RefreshStampBackfillFixedRows = 2,
            RefreshStampBackfillAfterBatch = batch =>
                batch == 2 ? throw new InvalidOperationException("stopped") : Task.CompletedTask,
        };
        var ex = await Record.ExceptionAsync(() => stopping.InitializeAsync());
        Assert.IsType<InvalidOperationException>(ex);

        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(0L, await LedgerCountAsync(conn));
            var stamps = await RefreshStampSeed.StampsAsync(conn);
            Assert.Equal(RefreshStampSeed.Expected.Take(4).ToList(), stamps.Take(4).ToList());
            Assert.Equal(RefreshStampSeed.Seeded.Skip(4).ToList(), stamps.Skip(4).ToList());
        }

        var batches = new List<int>();
        var finishing = new SchemaInitializer(_db)
        {
            RefreshStampBackfillFixedRows = 2,
            RefreshStampBackfillAfterBatch = batch =>
            {
                batches.Add(batch);
                return Task.CompletedTask;
            },
        };
        await finishing.InitializeAsync();

        Assert.Equal([1, 2, 3, 4], batches);
        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(1L, await LedgerCountAsync(conn));
            Assert.Equal(RefreshStampSeed.Expected, await RefreshStampSeed.StampsAsync(conn));
        }
    }

    private static Task<long> LedgerCountAsync(DbConnection conn) =>
        conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name = @Migration", new { Migration });
}

/// <summary>
/// Seed shared by the SQLite tests above and the live-Postgres run: two orgs reaching four shared
/// artifacts, one artifact with no shared stamp, and one tenant row already stamped.
/// </summary>
internal static class RefreshStampSeed
{
    private const string Stamp1 = "2026-01-01T00:00:00Z";
    private const string Stamp2 = "2026-01-02T00:00:00Z";
    private const string Stamp4 = "2026-01-04T00:00:00Z";
    private const string OwnStamp = "2026-05-05T00:00:00Z";

    // Every tenant row in primary-key order, as seeded.
    public static readonly IReadOnlyList<(string Org, string Artifact, string? Stamp)> Seeded =
    [
        ("org-a", "ca-1", null),
        ("org-a", "ca-2", null),
        ("org-a", "ca-3", null),
        ("org-a", "ca-4", null),
        ("org-b", "ca-1", null),
        ("org-b", "ca-2", OwnStamp),
        ("org-b", "ca-3", null),
    ];

    // The same rows once the backfill has finished: each NULL inherits the shared stamp, ca-3 has
    // none to inherit and stays NULL, and org-b's own stamp on ca-2 is left alone.
    public static readonly IReadOnlyList<(string Org, string Artifact, string? Stamp)> Expected =
    [
        ("org-a", "ca-1", Stamp1),
        ("org-a", "ca-2", Stamp2),
        ("org-a", "ca-3", null),
        ("org-a", "ca-4", Stamp4),
        ("org-b", "ca-1", Stamp1),
        ("org-b", "ca-2", OwnStamp),
        ("org-b", "ca-3", null),
    ];

    public static async Task SeedAsync(DbConnection conn)
    {
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-a', 'org-a'), ('org-b', 'org-b')");
        foreach ((string id, string? stamp) in new[]
                 { ("ca-1", Stamp1), ("ca-2", Stamp2), ("ca-3", (string?)null), ("ca-4", Stamp4) })
        {
            // xtenant: cache_artifact is the global proxy plane; it has no tenant column.
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, deprecation_checked_at)
                VALUES (@id, 'npm', @id, '1.0.0', @id, 'proxy/' || @id, @id, @stamp)
                """,
                new { id, stamp });
        }

        foreach ((string org, string artifact, string? stamp) in Seeded)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, refresh_checked_at)
                VALUES (@org, @artifact, @stamp)
                """,
                new { org, artifact, stamp });
        }
    }

    public static async Task<List<(string Org, string Artifact, string? Stamp)>> StampsAsync(DbConnection conn) =>
        // xtenant: the test reads every seeded tenant's rows back to compare them.
        (await conn.QueryAsync<(string Org, string Artifact, string? Stamp)>(
            """
            SELECT org_id, cache_artifact_id, refresh_checked_at FROM tenant_artifact_access
            WHERE org_id IN ('org-a', 'org-b')
            ORDER BY org_id, cache_artifact_id
            """)).ToList();
}
