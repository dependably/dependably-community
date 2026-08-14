using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// A symbol-index rebuild (<see cref="NuGetSymbolIndexer.ReplaceIndexAsync"/>) deletes the
/// version's existing rows and re-inserts the freshly-extracted set. These pin that the two
/// halves are atomic: a failure partway through the insert loop (SQLITE_BUSY, a dropped
/// connection, cancellation) must roll back to the version's previous, working index rather
/// than leaving it partially populated or empty.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetSymbolIndexerAtomicityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _blobRoot = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await OrgSeeder.InsertAsync(_db, "acme", default);
        // Overwrite with a fixed id so downstream inserts can hardcode "o1".
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM orgs");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o1')");

        _blobRoot = Path.Combine(Path.GetTempPath(), $"dependably-symidx-test-{Guid.NewGuid():N}");
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        if (Directory.Exists(_blobRoot))
        {
            Directory.Delete(_blobRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ReplaceIndexAsync_FailurePartwayThroughInsert_LeavesPreviousIndexIntact()
    {
        string pkgId = await PackageSeeder.InsertAsync(_db, "o1", "nuget", "pkg");
        string versionId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:nuget/pkg@1.0.0", blobKey: "hosted/pkg/1.0.0/pkg.1.0.0.nupkg");

        var blobs = new LocalBlobStore(_blobRoot);
        var repo = new NuGetSymbolIndexRepository(_db, TestTime.Frozen());
        var indexer = new NuGetSymbolIndexer(repo, blobs, NullLogger<NuGetSymbolIndexer>.Instance);

        // Establish a working index for the version — this is what a failed rebuild must not
        // destroy.
        var oldSignature = Guid.NewGuid();
        byte[] oldSnupkg = NuGetFixtures.BuildSnupkgWithPdbs(
            "pkg", "1.0.0", ("old.pdb", NuGetFixtures.BuildPortablePdb(oldSignature)));
        using (var oldStream = new MemoryStream(oldSnupkg))
        {
            int indexed = await indexer.ReplaceIndexAsync("o1", versionId, "hosted/old.snupkg", oldStream);
            Assert.Equal(1, indexed);
        }

        string oldKey = NuGetSymbolKey.PortableKey(oldSignature);
        Assert.NotNull(await repo.ResolveAsync("o1", "old.pdb", oldKey));

        // A rebuild carrying TWO new PDBs, the second of which fails to insert — simulating a
        // transient DB failure (SQLITE_BUSY, a dropped connection) partway through the rebuild.
        var newSig1 = Guid.NewGuid();
        var newSig2 = Guid.NewGuid();
        byte[] newSnupkg = NuGetFixtures.BuildSnupkgWithPdbs(
            "pkg", "1.0.0",
            ("new1.pdb", NuGetFixtures.BuildPortablePdb(newSig1)),
            ("new2.pdb", NuGetFixtures.BuildPortablePdb(newSig2)));

        var failingDb = new FailOnNthInsertMetadataStore(_db, failOnOccurrence: 2);
        var failingRepo = new NuGetSymbolIndexRepository(failingDb, TestTime.Frozen());
        var failingIndexer = new NuGetSymbolIndexer(failingRepo, blobs, NullLogger<NuGetSymbolIndexer>.Instance);

        using (var newStream = new MemoryStream(newSnupkg))
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => failingIndexer.ReplaceIndexAsync("o1", versionId, "hosted/new.snupkg", newStream));
        }

        // Regression: the failed rebuild must not have wiped the previous, working index —
        // read back with the real (non-failing) repo/store.
        Assert.NotNull(await repo.ResolveAsync("o1", "old.pdb", oldKey));
        Assert.Null(await repo.ResolveAsync("o1", "new1.pdb", NuGetSymbolKey.PortableKey(newSig1)));
        Assert.Null(await repo.ResolveAsync("o1", "new2.pdb", NuGetSymbolKey.PortableKey(newSig2)));
    }

    /// <summary>
    /// Metadata-store decorator that throws on the Nth statement whose text matches an INSERT
    /// into <c>nuget_symbol_index</c> — regardless of which connection issued it, so it
    /// reproduces a mid-rebuild failure whether the delete and the inserts share one connection
    /// (the atomic implementation) or run on separate ones (the non-atomic shape this test
    /// guards against).
    /// </summary>
    private sealed class FailOnNthInsertMetadataStore(IMetadataStore inner, int failOnOccurrence) : IMetadataStore
    {
        private int _count;

        public DbProvider Provider => inner.Provider;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = await inner.OpenAsync(ct);
            return new FaultConnection(conn, this);
        }

        private void MaybeFail(string commandText)
        {
            if (!commandText.Contains("INSERT INTO nuget_symbol_index", StringComparison.Ordinal))
            {
                return;
            }

            if (Interlocked.Increment(ref _count) == failOnOccurrence)
            {
                throw new InvalidOperationException("simulated symbol-index insert failure");
            }
        }

        private sealed class FaultConnection(DbConnection inner, FailOnNthInsertMetadataStore owner) : DbConnection
        {
            [AllowNull]
            public override string ConnectionString
            {
                get => inner.ConnectionString;
                set => inner.ConnectionString = value;
            }

            public override string Database => inner.Database;
            public override string DataSource => inner.DataSource;
            public override string ServerVersion => inner.ServerVersion;
            public override ConnectionState State => inner.State;

            public override void ChangeDatabase(string databaseName) => inner.ChangeDatabase(databaseName);
            public override void Close() => inner.Close();
            public override void Open() => inner.Open();
            public override Task OpenAsync(CancellationToken ct) => inner.OpenAsync(ct);

            protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
                inner.BeginTransaction(isolationLevel);

            protected override DbCommand CreateDbCommand() => new FaultCommand(inner.CreateCommand(), this, owner);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }

                base.Dispose(disposing);
            }

            public override async ValueTask DisposeAsync()
            {
                await inner.DisposeAsync();
                await base.DisposeAsync();
                GC.SuppressFinalize(this);
            }
        }

        private sealed class FaultCommand(DbCommand inner, FaultConnection connOwner, FailOnNthInsertMetadataStore storeOwner)
            : DbCommand
        {
            [AllowNull]
            public override string CommandText
            {
                get => inner.CommandText;
                set => inner.CommandText = value;
            }

            public override int CommandTimeout
            {
                get => inner.CommandTimeout;
                set => inner.CommandTimeout = value;
            }

            public override CommandType CommandType
            {
                get => inner.CommandType;
                set => inner.CommandType = value;
            }

            public override bool DesignTimeVisible
            {
                get => inner.DesignTimeVisible;
                set => inner.DesignTimeVisible = value;
            }

            public override UpdateRowSource UpdatedRowSource
            {
                get => inner.UpdatedRowSource;
                set => inner.UpdatedRowSource = value;
            }

            protected override DbConnection? DbConnection
            {
                get => connOwner;
                set { /* the inner command keeps its real connection */ }
            }

            protected override DbParameterCollection DbParameterCollection => inner.Parameters;

            protected override DbTransaction? DbTransaction
            {
                get => inner.Transaction;
                set => inner.Transaction = value;
            }

            public override void Cancel() => inner.Cancel();

            protected override DbParameter CreateDbParameter() => inner.CreateParameter();

            public override int ExecuteNonQuery()
            {
                storeOwner.MaybeFail(inner.CommandText);
                return inner.ExecuteNonQuery();
            }

            public override Task<int> ExecuteNonQueryAsync(CancellationToken ct)
            {
                storeOwner.MaybeFail(inner.CommandText);
                return inner.ExecuteNonQueryAsync(ct);
            }

            public override object? ExecuteScalar() => inner.ExecuteScalar();

            public override Task<object?> ExecuteScalarAsync(CancellationToken ct) => inner.ExecuteScalarAsync(ct);

            public override void Prepare() => inner.Prepare();

            protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) =>
                inner.ExecuteReader(behavior);

            protected override Task<DbDataReader> ExecuteDbDataReaderAsync(
                CommandBehavior behavior, CancellationToken ct) =>
                inner.ExecuteReaderAsync(behavior, ct);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }

                base.Dispose(disposing);
            }
        }
    }
}
