using System.Data.Common;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;

namespace Dependably.Infrastructure.Migration;

/// <summary>How the copy should treat a target that is not pristine, and whether to verify afterwards.</summary>
public sealed record MetadataMigrationOptions
{
    /// <summary>
    /// Overwrite a target that already holds data. Without it a target with any operator row in it
    /// is refused outright — an accidental run against the live Postgres of another environment is
    /// unrecoverable, so it takes an explicit flag.
    /// </summary>
    public bool Force { get; init; }

    /// <summary>Skip the post-copy verification pass (it can be run standalone later).</summary>
    public bool SkipVerification { get; init; }
}

/// <summary>What one table's copy produced.</summary>
public sealed record TableCopyResult(string Table, long Rows, int Columns);

/// <summary>The outcome of a full copy.</summary>
public sealed record MetadataMigrationResult(
    IReadOnlyList<TableCopyResult> Tables,
    IReadOnlyList<string> SkippedTables,
    IReadOnlyList<string> ResetSequences,
    bool ForeignKeysBypassed,
    MigrationVerificationReport? Verification)
{
    public long TotalRows => Tables.Sum(t => t.Rows);
}

/// <summary>
/// Copies an entire dependably SQLite database into a Postgres database, table by table, in
/// foreign-key order, preserving primary keys and timestamps exactly.
///
/// <para>The shape of the target is not assumed: the migrator runs the production
/// <see cref="SchemaInitializer"/> against it first, so the destination is the same schema the
/// running application would create, down to the additive columns and the one-time migrations.
/// Only then are the column plans resolved, from both live catalogues.</para>
///
/// <para>Rows are written with the Postgres binary COPY protocol, with each value coerced to the
/// target column's exact type by <see cref="PostgresValueConverter"/>. Nothing is left to implicit
/// conversion: SQLite's dynamic typing means a declared type is a hint, not a guarantee, and an
/// implicit coercion is precisely how a migration corrupts data without failing.</para>
/// </summary>
public sealed class SqliteToPostgresMigrator
{
    private readonly IMetadataStore _source;
    private readonly IMetadataStore _target;
    private readonly ILogger<SqliteToPostgresMigrator> _logger;
    private readonly SchemaInitializer? _targetInitializer;

    public SqliteToPostgresMigrator(
        IMetadataStore source,
        IMetadataStore target,
        ILogger<SqliteToPostgresMigrator>? logger = null,
        SchemaInitializer? targetInitializer = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);

        if (source.Provider != DbProvider.Sqlite)
        {
            throw new MetadataMigrationException("The migration source must be a SQLite metadata store.");
        }

        if (target.Provider != DbProvider.Postgres)
        {
            throw new MetadataMigrationException("The migration target must be a Postgres metadata store.");
        }

        _source = source;
        _target = target;
        _logger = logger ?? NullLogger<SqliteToPostgresMigrator>.Instance;
        _targetInitializer = targetInitializer;
    }

    /// <summary>Copies every table, resets identity sequences, and (by default) verifies the result.</summary>
    public Task<MetadataMigrationResult> MigrateAsync(
        MetadataMigrationOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        return MigrateCoreAsync(options, ct);
    }

    private async Task<MetadataMigrationResult> MigrateCoreAsync(
        MetadataMigrationOptions options, CancellationToken ct)
    {
        await using var sqlite = await _source.OpenAsync(ct);
        var plan = await MigrationTablePlan.DiscoverAsync(sqlite, ct);
        _logger.LogInformation(
            "Migration plan derived from the source database: {TableCount} tables in foreign-key order",
            plan.Tables.Count);

        if (plan.HasCycle)
        {
            _logger.LogWarning(
                "The source foreign-key graph contains a cycle; some tables could not be ordered parent-first. " +
                "The copy will still run, but a child may precede its parent and fail on a foreign key.");
        }

        var orphans = await FindOrphanRowsAsync(sqlite, ct);

        await using var pgConn = await _target.OpenAsync(ct);
        var pg = pgConn as NpgsqlConnection
            ?? throw new MetadataMigrationException("The migration target did not yield an Npgsql connection.");

        bool pristine = await IsPristineAsync(pg, ct);
        await InitializeTargetSchemaAsync(ct);

        var columnPlans = new Dictionary<string, TableColumnPlan>(StringComparer.OrdinalIgnoreCase);
        var skipped = new List<string>();
        foreach (string table in plan.Tables)
        {
            var columnPlan = await MigrationColumnPlanner.BuildAsync(sqlite, pg, table, ct);
            if (columnPlan is null)
            {
                skipped.Add(table);
                _logger.LogWarning(
                    "Table {Table} exists in the SQLite source but not in the current schema; its rows are not " +
                    "migrated. This is a table a later release dropped — confirm no data you need lives there.",
                    table);
                continue;
            }

            columnPlans[table] = columnPlan;
            await WarnOnTargetOnlyColumnsAsync(sqlite, pg, columnPlan, ct);
        }

        await GuardTargetOccupancyAsync(pg, columnPlans.Keys, pristine, options.Force, ct);

        bool bypassed = await TryBypassForeignKeysAsync(pg, ct);
        if (!bypassed && orphans.Count > 0)
        {
            throw new MetadataMigrationException(
                $"The source holds {orphans.Count} row(s) whose foreign keys do not resolve, and this Postgres " +
                $"role may not disable foreign-key enforcement for the copy (SET session_replication_role " +
                $"requires a superuser). Postgres would reject those rows. Either connect as a superuser or " +
                $"delete the dangling rows first: {string.Join("; ", orphans.Take(20))}");
        }

        try
        {
            await ClearTargetAsync(pg, columnPlans.Keys, ct);

            var results = new List<TableCopyResult>(columnPlans.Count);
            foreach (string table in plan.Tables)
            {
                if (!columnPlans.TryGetValue(table, out var columnPlan))
                {
                    continue;
                }

                long rows = await CopyTableAsync(sqlite, pg, columnPlan, ct);
                results.Add(new TableCopyResult(table, rows, columnPlan.Columns.Count));
                _logger.LogInformation("Copied {Rows} row(s) into {Table}", rows, table);
            }

            var sequences = await ResetSequencesAsync(pg, columnPlans.Keys, ct);

            MigrationVerificationReport? verification = null;
            if (!options.SkipVerification)
            {
                verification = await MigrationVerifier.VerifyAsync(sqlite, pg, plan, ct);
                LogVerification(verification);
            }

            return new MetadataMigrationResult(results, skipped, sequences, bypassed, verification);
        }
        finally
        {
            if (bypassed)
            {
                await RestoreForeignKeysAsync(pg);
            }
        }
    }

    /// <summary>
    /// Verifies an already-migrated target against the source. Runs standalone — it derives the
    /// table and column plans from the two live catalogues and touches neither database's contents.
    /// </summary>
    public async Task<MigrationVerificationReport> VerifyAsync(CancellationToken ct = default)
    {
        await using var sqlite = await _source.OpenAsync(ct);
        await using var pg = await _target.OpenAsync(ct);
        var plan = await MigrationTablePlan.DiscoverAsync(sqlite, ct);
        var report = await MigrationVerifier.VerifyAsync(sqlite, pg, plan, ct);
        LogVerification(report);
        return report;
    }

    private async Task InitializeTargetSchemaAsync(CancellationToken ct)
    {
        var initializer = _targetInitializer ?? new SchemaInitializer(_target);
        await initializer.InitializeAsync(ct);
        _logger.LogInformation("Applied the current schema to the Postgres target");
    }

    /// <summary>True when the target has no dependably schema at all — never been booted against.</summary>
    private static async Task<bool> IsPristineAsync(DbConnection pg, CancellationToken ct)
    {
        // xtenant: counts base tables in the target database's catalogue; not a tenant-scoped read.
        long tables = await pg.ExecuteScalarAsync<long>(new CommandDefinition(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """,
            cancellationToken: ct));
        return tables == 0;
    }

    /// <summary>
    /// Refuses to overwrite a target holding operator data unless forced. Rows the schema apply
    /// creates on its own (<see cref="MigrationTablePlan.SeedPopulatedTables"/>) are not operator
    /// data, so a Postgres that has only ever had the schema applied still counts as free.
    /// </summary>
    private async Task GuardTargetOccupancyAsync(
        DbConnection pg, IEnumerable<string> tables, bool pristine, bool force, CancellationToken ct)
    {
        if (pristine)
        {
            _logger.LogInformation("The Postgres target was empty before the schema apply");
            return;
        }

        var occupied = new List<string>();
        foreach (string table in tables)
        {
            if (MigrationTablePlan.SeedPopulatedTables.Contains(table))
            {
                continue;
            }

            // rawsql: the table name is a catalogue-derived identifier validated by
            // MigrationColumnPlanner.Quote; the statement carries no values and takes no parameters.
            // xtenant: an occupancy probe over the whole target database, by design not tenant-scoped.
            long rows = await pg.ExecuteScalarAsync<long>(new CommandDefinition(
                $"SELECT COUNT(*) FROM {MigrationColumnPlanner.Quote(table)}",
                cancellationToken: ct));
            if (rows > 0)
            {
                occupied.Add($"{table}={rows}");
            }
        }

        if (occupied.Count == 0)
        {
            _logger.LogInformation("The Postgres target has the schema but holds no operator data");
            return;
        }

        if (!force)
        {
            throw new MetadataMigrationException(
                $"The Postgres target already holds data and will not be overwritten: " +
                $"{string.Join(", ", occupied.Take(20))}. Point at an empty database, or re-run with --force " +
                $"to replace its contents with the SQLite source's.");
        }

        _logger.LogWarning(
            "--force: replacing existing data in the Postgres target ({Occupied})",
            string.Join(", ", occupied.Take(20)));
    }

    private async Task WarnOnTargetOnlyColumnsAsync(
        DbConnection sqlite, DbConnection pg, TableColumnPlan plan, CancellationToken ct)
    {
        var targetColumns = await MigrationColumnPlanner.PostgresColumnsAsync(pg, plan.Table, ct);
        var sourceColumns = await MigrationColumnPlanner.SqliteColumnsAsync(sqlite, plan.Table, ct);
        var extra = MigrationColumnPlanner.TargetOnlyColumns(targetColumns, sourceColumns);
        if (extra.Count > 0)
        {
            _logger.LogWarning(
                "Table {Table}: column(s) {Columns} exist only in the target and take their Postgres defaults",
                plan.Table, string.Join(", ", extra));
        }
    }

    /// <summary>
    /// Lists rows in the source whose foreign keys do not resolve. SQLite does not enforce foreign
    /// keys on rows written while enforcement was off, so an old database can carry orphans that
    /// Postgres would reject. Reporting them up front turns a mid-copy constraint error into a
    /// pre-flight diagnostic.
    /// </summary>
    private async Task<IReadOnlyList<string>> FindOrphanRowsAsync(DbConnection sqlite, CancellationToken ct)
    {
        // The pragma_* table-valued functions declare no column types, and Microsoft.Data.Sqlite
        // surfaces untyped columns as byte[]; CAST(... AS TEXT) pins each field to text so Dapper
        // materialises strings.
        // xtenant: PRAGMA foreign_key_check reports over the whole database; it has no tenant column.
        var rows = await sqlite.QueryAsync<(string Child, string? RowId, string Parent)>(
            new CommandDefinition(
                """
                SELECT CAST("table" AS TEXT)  AS Child,
                       CAST("rowid" AS TEXT)  AS RowId,
                       CAST("parent" AS TEXT) AS Parent
                FROM pragma_foreign_key_check
                """,
                cancellationToken: ct));

        var orphans = rows
            .Select(r => $"{r.Child} rowid={r.RowId ?? "?"} -> {r.Parent}")
            .ToList();

        if (orphans.Count > 0)
        {
            _logger.LogWarning(
                "The source holds {Count} row(s) with unresolvable foreign keys; they are preserved verbatim " +
                "with enforcement bypassed for the copy: {Sample}",
                orphans.Count, string.Join("; ", orphans.Take(20)));
        }

        return orphans;
    }

    /// <summary>
    /// Turns off foreign-key trigger firing for this session so the copy reproduces the source
    /// exactly, orphans included — a reshape or a migration never changes which rows exist, and
    /// neither does this. Requires a superuser; a role without it gets a warning and enforcement
    /// stays on, which is safe as long as the source has no dangling rows.
    /// </summary>
    private async Task<bool> TryBypassForeignKeysAsync(DbConnection pg, CancellationToken ct)
    {
        try
        {
            await pg.ExecuteAsync(new CommandDefinition(
                "SET session_replication_role = replica", cancellationToken: ct));
            return true;
        }
        catch (PostgresException ex)
        {
            _logger.LogWarning(
                "Could not disable foreign-key enforcement for the copy ({ExceptionType}: {SqlState}); " +
                "the copy runs with constraints enforced",
                ex.GetType().Name, ex.SqlState);
            return false;
        }
    }

    private async Task RestoreForeignKeysAsync(DbConnection pg)
    {
        try
        {
            await pg.ExecuteAsync("SET session_replication_role = DEFAULT");
        }
        catch (PostgresException ex)
        {
            _logger.LogWarning(
                "Could not restore foreign-key enforcement on the migration session ({ExceptionType}: {SqlState}); " +
                "the session is discarded when the connection closes",
                ex.GetType().Name, ex.SqlState);
        }
    }

    /// <summary>
    /// Empties the target's migrated tables so the copy lands on a clean slate. Even a pristine
    /// target needs this: the schema apply seeds the SPDX licence catalogue, and the source carries
    /// the same rows, so a copy onto the seeded table would collide on the primary key.
    /// </summary>
    private async Task ClearTargetAsync(DbConnection pg, IEnumerable<string> tables, CancellationToken ct)
    {
        var quoted = tables.Select(MigrationColumnPlanner.Quote).ToList();
        if (quoted.Count == 0)
        {
            return;
        }

        // rawsql: every identifier is a catalogue-derived table name validated by
        // MigrationColumnPlanner.Quote; the statement carries no values and takes no parameters.
        // xtenant: clears the whole target database ahead of a full-database copy, by design.
        await pg.ExecuteAsync(new CommandDefinition(
            "TRUNCATE TABLE " + string.Join(", ", quoted) + " RESTART IDENTITY CASCADE",
            cancellationToken: ct));
        _logger.LogInformation("Cleared {TableCount} target table(s) ahead of the copy", quoted.Count);
    }

    private static async Task<long> CopyTableAsync(
        DbConnection sqlite, NpgsqlConnection pg, TableColumnPlan plan, CancellationToken ct)
    {
        // rawsql: table/column identifiers come from the live catalogue and are validated by
        // MigrationColumnPlanner.Quote; COPY FROM STDIN carries its values on the binary stream,
        // never in the statement text.
        string copySql =
            $"COPY {MigrationColumnPlanner.Quote(plan.Table)} " +
            $"({string.Join(", ", plan.Columns.Select(c => MigrationColumnPlanner.Quote(c.Name)))}) " +
            $"FROM STDIN (FORMAT BINARY)";

        await using var cmd = sqlite.CreateCommand();
        cmd.CommandText = MigrationVerifier.SelectSql(plan);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        long rows = 0;
        await using var writer = await pg.BeginBinaryImportAsync(copySql, ct);
        while (await reader.ReadAsync(ct))
        {
            await writer.StartRowAsync(ct);
            for (int i = 0; i < plan.Columns.Count; i++)
            {
                var column = plan.Columns[i];
                object? raw = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                object? converted = PostgresValueConverter.ToPostgresValue(plan.Table, column, raw);
                await WriteValueAsync(writer, column.Kind, converted, ct);
            }

            rows++;
        }

        await writer.CompleteAsync(ct);
        return rows;
    }

    /// <summary>
    /// Writes one already-converted value through the strongly typed COPY overload for its storage
    /// class. Dispatching on the resolved kind (rather than handing Npgsql an <c>object</c>) keeps
    /// the CLR type, the declared wire type, and the target column provably in agreement.
    /// </summary>
    private static async Task WriteValueAsync(
        NpgsqlBinaryImporter writer, PostgresKind kind, object? value, CancellationToken ct)
    {
        if (value is null)
        {
            await writer.WriteNullAsync(ct);
            return;
        }

        var wire = PostgresValueConverter.WireType(kind);
        switch (kind)
        {
            case PostgresKind.Text:
            case PostgresKind.Json:
            case PostgresKind.Jsonb:
                await writer.WriteAsync((string)value, wire, ct);
                break;
            case PostgresKind.SmallInt:
                await writer.WriteAsync((short)value, wire, ct);
                break;
            case PostgresKind.Integer:
                await writer.WriteAsync((int)value, wire, ct);
                break;
            case PostgresKind.BigInt:
                await writer.WriteAsync((long)value, wire, ct);
                break;
            case PostgresKind.Real:
                await writer.WriteAsync((float)value, wire, ct);
                break;
            case PostgresKind.DoublePrecision:
                await writer.WriteAsync((double)value, wire, ct);
                break;
            case PostgresKind.Numeric:
                await writer.WriteAsync((decimal)value, wire, ct);
                break;
            case PostgresKind.Boolean:
                await writer.WriteAsync((bool)value, wire, ct);
                break;
            case PostgresKind.TimestampTz:
            case PostgresKind.Timestamp:
                await writer.WriteAsync((DateTime)value, wire, ct);
                break;
            case PostgresKind.Date:
                await writer.WriteAsync((DateOnly)value, wire, ct);
                break;
            case PostgresKind.Bytea:
                await writer.WriteAsync((byte[])value, wire, ct);
                break;
            case PostgresKind.Uuid:
                await writer.WriteAsync((Guid)value, wire, ct);
                break;
            default:
                throw new MetadataMigrationException($"No COPY writer for {kind}.");
        }
    }

    /// <summary>
    /// Re-points every identity/serial sequence past the largest value the copy just inserted.
    /// Rows carry their original primary keys, so a sequence left at its initial value hands the
    /// next insert an id that already exists — the classic post-restore duplicate-key failure.
    /// The sequences are discovered from the catalogue, not listed here, so a future identity
    /// column is covered without a code change.
    /// </summary>
    private async Task<IReadOnlyList<string>> ResetSequencesAsync(
        DbConnection pg, IEnumerable<string> tables, CancellationToken ct)
    {
        var migrated = new HashSet<string>(tables, StringComparer.OrdinalIgnoreCase);

        // xtenant: catalogue enumeration of identity sequences across the target database.
        var candidates = await pg.QueryAsync<(string TableName, string ColumnName, string? Sequence)>(
            new CommandDefinition(
                """
                SELECT c.table_name AS TableName,
                       c.column_name AS ColumnName,
                       pg_get_serial_sequence(quote_ident(c.table_schema) || '.' || quote_ident(c.table_name),
                                              c.column_name) AS Sequence
                FROM information_schema.columns c
                JOIN information_schema.tables t
                  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
                WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
                """,
                cancellationToken: ct));

        var reset = new List<string>();
        foreach (var (table, column, sequence) in candidates)
        {
            if (string.IsNullOrEmpty(sequence) || !migrated.Contains(table))
            {
                continue;
            }

            // rawsql: the table and column names are catalogue-derived identifiers validated by
            // MigrationColumnPlanner.Quote; the sequence name is bound as the @sequence parameter.
            // xtenant: post-copy sequence repair over the whole target database, by design.
            await pg.ExecuteAsync(new CommandDefinition(
                $"SELECT setval(@sequence, COALESCE((SELECT MAX({MigrationColumnPlanner.Quote(column)}) " +
                $"FROM {MigrationColumnPlanner.Quote(table)}), 0) + 1, false)",
                new { sequence },
                cancellationToken: ct));
            reset.Add($"{table}.{column}");
        }

        if (reset.Count > 0)
        {
            _logger.LogInformation("Reset {Count} identity sequence(s): {Sequences}", reset.Count, string.Join(", ", reset));
        }

        return reset;
    }

    private void LogVerification(MigrationVerificationReport report)
    {
        if (report.Ok)
        {
            _logger.LogInformation(
                "Verification passed: {TableCount} table(s), {Rows} row(s) match by count and content " +
                "({SkippedCount} source table(s) skipped as absent from the current schema)",
                report.Tables.Count, report.TotalTargetRows, report.SkippedTables.Count);
            return;
        }

        if (report.Tables.Count == 0)
        {
            _logger.LogError(
                "Verification FAILED: not one table could be compared — the target has none of the " +
                "source's {SkippedCount} table(s). Is this the right database, and has the migration run?",
                report.SkippedTables.Count);
            return;
        }

        foreach (var failure in report.Failures)
        {
            _logger.LogError(
                "Verification FAILED for {Table}: source {SourceRows} row(s)/{SourceDigest}, " +
                "target {TargetRows} row(s)/{TargetDigest}",
                failure.Table, failure.SourceRows, failure.SourceDigest, failure.TargetRows, failure.TargetDigest);
        }

        _logger.LogError(
            "Verification FAILED for {FailureCount} of {TableCount} table(s). Do not cut over.",
            report.Failures.Count, report.Tables.Count);
    }
}
