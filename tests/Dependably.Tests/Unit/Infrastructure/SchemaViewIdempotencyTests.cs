using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// A replica boot is not a schema change. Every task start — a rolling restart, an autoscaling
/// scale-out, the green slot of a blue-green cutover — applies the schema against a database other
/// replicas are already querying, so any DDL a steady-state boot performs is DDL a live reader can
/// trip over. <c>org_storage_bytes</c> makes that concrete: it is the quota read path.
///
/// These pin both halves of the guarantee on SQLite — that a boot changing nothing performs no view
/// DDL at all, and that a boot whose view definition genuinely changed still replaces it. The
/// Postgres half (<c>CREATE OR REPLACE VIEW</c> and its guarded drop+create fallback) is pinned by
/// PostgresSchemaApplyTests, which needs a live server.
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaViewIdempotencyTests : IAsyncLifetime
{
    private const string ViewName = "org_storage_bytes";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// SQLite bumps <c>schema_version</c> on every DDL statement that actually changes the schema —
    /// and leaves it alone for the <c>IF NOT EXISTS</c> no-ops the base pass and the additive
    /// migrations are made of. So an unchanged counter across a second apply is a precise statement
    /// that the boot dropped and created nothing, which is the only way a concurrent reader is
    /// guaranteed never to miss a view.
    /// </summary>
    [Fact]
    public async Task SecondApply_PerformsNoSchemaChangingDdl()
    {
        long before = await SchemaVersionAsync();
        Assert.True(before > 0, "schema_version should be non-zero after the first apply");

        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(before, await SchemaVersionAsync());
    }

    /// <summary>
    /// The behavioural form of the same guarantee: a reader on its own connection polls the view for
    /// the whole duration of a second apply and must never be told the object does not exist.
    /// </summary>
    [Fact]
    public async Task ConcurrentReader_NeverSeesTheViewMissing_DuringASecondApply()
    {
        var missing = new List<string>();
        using var stop = new CancellationTokenSource();

        var reader = Task.Run(async () =>
        {
            await using var conn = await _db.OpenAsync();
            long polls = 0;
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    // xtenant: the view groups by org_id; this probe only asserts the object resolves.
                    await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM org_storage_bytes");
                }
                catch (DbException ex) when (ex.Message.Contains("no such table", StringComparison.OrdinalIgnoreCase))
                {
                    lock (missing)
                    {
                        missing.Add(ex.Message);
                    }
                }

                polls++;
                await Task.Yield();
            }

            return polls;
        });

        await new SchemaInitializer(_db).InitializeAsync();
        await stop.CancelAsync();
        long polled = await reader;

        Assert.True(polled > 0, "the reader never got to poll — the test proves nothing");
        lock (missing)
        {
            Assert.True(missing.Count == 0,
                $"a concurrent reader saw {ViewName} missing {missing.Count} time(s) during a re-apply");
        }
    }

    /// <summary>
    /// The other side of the conditional: when the stored definition genuinely differs, the boot must
    /// still replace it, or a view body change would never reach an existing database.
    /// </summary>
    [Fact]
    public async Task ChangedDefinition_IsReplacedByTheCanonicalBody()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DROP VIEW org_storage_bytes");
            // xtenant: stand-in view body for the test; org_id is projected exactly as the real one.
            await conn.ExecuteAsync(
                "CREATE VIEW org_storage_bytes AS SELECT o.id AS org_id, 0 AS total_bytes FROM orgs o");
        }

        await new SchemaInitializer(_db).InitializeAsync();

        string stored = await StoredDefinitionAsync();
        Assert.Contains("SUM(sb.bytes)", stored, StringComparison.Ordinal);
    }

    /// <summary>
    /// Whitespace is not a definition change. Normalizing before comparing is what keeps a reindented
    /// view body — or a database written by a build whose formatting differed — from reintroducing a
    /// drop on every boot, which is the failure this whole mechanism exists to remove.
    /// </summary>
    [Fact]
    public async Task ReindentedDefinition_IsNotTreatedAsAChange()
    {
        string reindented = (await StoredDefinitionAsync()).Replace("\n", "\n    ", StringComparison.Ordinal);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DROP VIEW org_storage_bytes");
            await conn.ExecuteAsync(reindented);
        }

        long before = await SchemaVersionAsync();
        await new SchemaInitializer(_db).InitializeAsync();

        Assert.Equal(before, await SchemaVersionAsync());
        Assert.Equal(reindented, await StoredDefinitionAsync());
    }

    private async Task<long> SchemaVersionAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>("PRAGMA schema_version");
    }

    private async Task<string> StoredDefinitionAsync()
    {
        await using var conn = await _db.OpenAsync();
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = @name", new { name = ViewName });
        Assert.NotNull(sql);
        return sql;
    }
}
