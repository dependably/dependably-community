using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the fix for the storage-quota double-decrement race in
/// <see cref="PackageRepository.DeleteVersionAsync"/>: two concurrent deletes of the same
/// version must decrement <c>org_settings.storage_used_bytes</c> exactly once, not once per
/// caller. A sequential double-delete does not reproduce the bug — the second call's SELECT
/// would already see the row gone — so this drives a genuine race with a
/// <see cref="Barrier"/> gate that forces both callers' reads to complete before either's
/// delete lands, deterministically (no sleeps) reproducing the interleaving the old code got
/// wrong.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageRepositoryDeleteVersionRaceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task DeleteVersionAsync_TwoConcurrentDeletesOfSameVersion_DecrementsCounterExactlyOnce()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raced-delete");
        const long versionSize = 500;
        string versionId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/raced-delete@1.0.0", sizeBytes: versionSize);

        // Start the counter well clear of the MAX(0, …) clamp floor: 10_000 - 500 = 9_500 on a
        // correct single decrement vs. 9_000 on a double decrement — both values are positive,
        // so the clamp can't accidentally mask the bug the way it would if the counter started
        // at exactly `versionSize`.
        const long startingCounter = 10_000;
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET storage_used_bytes = @v WHERE org_id = @orgId",
                new { v = startingCounter, orgId });
        }

        // Both racing calls' pre-delete SELECT must complete before either proceeds to its
        // DELETE — this two-party barrier forces exactly that interleaving on every run.
        // Neither participant holds an open transaction while blocked at the barrier (the
        // SELECT runs autocommit, before DeleteVersionAsync opens its transaction), so this
        // cannot deadlock against the other racer's transaction.
        using var selectBarrier = new Barrier(2);
        var gatedDb = new GatingMetadataStore(_db, selectBarrier);
        var repo = new PackageRepository(gatedDb);

        var task1 = Task.Run(() => repo.DeleteVersionAsync(versionId));
        var task2 = Task.Run(() => repo.DeleteVersionAsync(versionId));
        var raceTask = Task.WhenAll(task1, task2);

        // Bounded wait: a regression that reintroduces a lock-order deadlock must fail loudly,
        // not hang the suite.
        var winner = await Task.WhenAny(raceTask, Task.Delay(TimeSpan.FromSeconds(30)));
        Assert.Same(raceTask, winner);
        await raceTask;

        long remainingRows;
        long finalCounter;
        await using (var conn = await _db.OpenAsync())
        {
            remainingRows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id = versionId });
            finalCounter = await conn.ExecuteScalarAsync<long>(
                "SELECT storage_used_bytes FROM org_settings WHERE org_id = @orgId", new { orgId });
        }

        Assert.Equal(0, remainingRows);
        Assert.Equal(startingCounter - versionSize, finalCounter);
    }

    // ── Gating IMetadataStore: pauses the version-lookup SELECT on a shared barrier ─────────

    /// <summary>
    /// Wraps an inner <see cref="IMetadataStore"/> so that the specific SELECT
    /// <see cref="PackageRepository.DeleteVersionAsync"/> issues to resolve a version's org/size
    /// blocks on <paramref name="selectBarrier"/> immediately after it executes (and before
    /// control returns to the caller). With a two-party barrier and two concurrent callers, this
    /// deterministically forces both reads to land before either caller's subsequent DELETE.
    /// </summary>
    private sealed class GatingMetadataStore : IMetadataStore
    {
        private readonly IMetadataStore _inner;
        private readonly Barrier _selectBarrier;

        public GatingMetadataStore(IMetadataStore inner, Barrier selectBarrier)
        {
            _inner = inner;
            _selectBarrier = selectBarrier;
        }

        public DbProvider Provider => _inner.Provider;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = await _inner.OpenAsync(ct);
            return new GatingConnection(conn, _selectBarrier);
        }
    }

    private sealed class GatingConnection : DbConnection
    {
        private readonly DbConnection _inner;
        private readonly Barrier _selectBarrier;

        public GatingConnection(DbConnection inner, Barrier selectBarrier)
        {
            _inner = inner;
            _selectBarrier = selectBarrier;
        }

        [AllowNull]
        public override string ConnectionString
        {
            get => _inner.ConnectionString;
            set => _inner.ConnectionString = value!;
        }

        public override string Database => _inner.Database;
        public override string DataSource => _inner.DataSource;
        public override string ServerVersion => _inner.ServerVersion;
        public override ConnectionState State => _inner.State;

        public override void ChangeDatabase(string databaseName) => _inner.ChangeDatabase(databaseName);
        public override void Close() => _inner.Close();
        public override void Open() => _inner.Open();

        protected override DbCommand CreateDbCommand() => new GatingCommand(_inner.CreateCommand(), _selectBarrier);

        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
            _inner.BeginTransaction(isolationLevel);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _inner.DisposeAsync();
            await base.DisposeAsync();
        }
    }

    private sealed class GatingCommand : DbCommand
    {
        private readonly DbCommand _inner;
        private readonly Barrier _selectBarrier;

        public GatingCommand(DbCommand inner, Barrier selectBarrier)
        {
            _inner = inner;
            _selectBarrier = selectBarrier;
        }

        [AllowNull]
        public override string CommandText
        {
            get => _inner.CommandText;
            set => _inner.CommandText = value!;
        }

        public override int CommandTimeout
        {
            get => _inner.CommandTimeout;
            set => _inner.CommandTimeout = value;
        }

        public override CommandType CommandType
        {
            get => _inner.CommandType;
            set => _inner.CommandType = value;
        }

        public override bool DesignTimeVisible
        {
            get => _inner.DesignTimeVisible;
            set => _inner.DesignTimeVisible = value;
        }

        public override UpdateRowSource UpdatedRowSource
        {
            get => _inner.UpdatedRowSource;
            set => _inner.UpdatedRowSource = value;
        }

        protected override DbConnection? DbConnection { get; set; }

        protected override DbParameterCollection DbParameterCollection => _inner.Parameters;

        protected override DbTransaction? DbTransaction
        {
            get => _inner.Transaction;
            set => _inner.Transaction = value;
        }

        protected override DbParameter CreateDbParameter() => _inner.CreateParameter();

        public override void Cancel() => _inner.Cancel();
        public override void Prepare() => _inner.Prepare();
        public override int ExecuteNonQuery() => _inner.ExecuteNonQuery();
        public override object? ExecuteScalar() => _inner.ExecuteScalar();

        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
        {
            var reader = _inner.ExecuteReader(behavior);

            // Only DeleteVersionAsync's version-lookup SELECT gates on the barrier — matched by
            // a fragment unique to that query. It runs autocommit (before DeleteVersionAsync
            // opens its transaction), so pausing here holds no lock and cannot deadlock against
            // the other racer's later transaction.
            if (_inner.CommandText.Contains("SELECT p.org_id AS OrgId", StringComparison.Ordinal))
            {
                _selectBarrier.SignalAndWait(TimeSpan.FromSeconds(10));
            }

            return reader;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
