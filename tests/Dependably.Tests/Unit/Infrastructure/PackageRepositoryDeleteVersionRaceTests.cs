using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Drives two concurrent <see cref="PackageRepository.DeleteVersionAsync"/> calls against the
/// same version through a <see cref="Barrier"/> that forces both callers' pre-delete reads to
/// land before either's DELETE — the interleaving a sequential double-delete cannot reproduce,
/// because the second call's SELECT would already see the row gone.
///
/// Both callers must converge on the same end state (row gone, <c>packages.is_proxy</c>
/// recomputed to match the surviving version set) and neither may deadlock against the other's
/// open transaction. Storage bytes need no assertion here: they are derived from the surviving
/// rows, so a delete has no counter to decrement once, twice, or at all.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageRepositoryDeleteVersionRaceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task DeleteVersionAsync_TwoConcurrentDeletesOfSameVersion_ConvergeOnOneEndState()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "raced-delete");
        string versionId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/raced-delete@1.0.0", sizeBytes: 500);
        var orgs = new OrgRepository(_db);
        Assert.Equal(500, await orgs.GetLiveStorageBytesAsync(orgId));

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
        long isProxy;
        await using (var conn = await _db.OpenAsync())
        {
            remainingRows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_versions WHERE id = @id", new { id = versionId });
            isProxy = await conn.ExecuteScalarAsync<long>(
                "SELECT is_proxy FROM packages WHERE id = @id", new { id = pkgId });
        }

        Assert.Equal(0, remainingRows);
        // The package's only uploaded version is gone, so it is a proxy-only package now.
        Assert.Equal(1, isProxy);
        // The deleted version's bytes leave the derived sum with the row — nothing to decrement.
        Assert.Equal(0, await orgs.GetLiveStorageBytesAsync(orgId));
    }

    // ── Gating IMetadataStore: pauses the version-lookup SELECT on a shared barrier ─────────

    /// <summary>
    /// Wraps an inner <see cref="IMetadataStore"/> so that the specific SELECT
    /// <see cref="PackageRepository.DeleteVersionAsync"/> issues to resolve a version's parent
    /// package blocks on <paramref name="selectBarrier"/> immediately after it executes (and before
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
            if (_inner.CommandText.Contains("SELECT package_id FROM package_versions", StringComparison.Ordinal))
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
