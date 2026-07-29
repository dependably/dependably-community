using System.Globalization;
using Dapper;

namespace Dependably.Infrastructure.Migration;

/// <summary>
/// The argv-driven one-shot modes that move a standalone SQLite deployment onto Postgres, and
/// verify that the move was complete. They ship inside the product image rather than as a separate
/// tool so an operator upgrading in place needs no second artefact and no second version to keep in
/// step with the schema:
///
/// <code>
///   Dependably migrate-to-postgres  [--source &lt;db-path&gt;] [--target &lt;conn&gt;] [--force] [--skip-verify]
///   Dependably verify-postgres-migration [--source &lt;db-path&gt;] [--target &lt;conn&gt;]
/// </code>
///
/// <para>Both default <c>--source</c> to <c>DB_PATH</c> and <c>--target</c> to
/// <c>DB_CONNECTION_STRING</c>, so a container already configured for either provider needs only
/// the missing half on the command line.</para>
/// </summary>
public static class DatabaseMigrationCommand
{
    /// <summary>Copies the SQLite database into Postgres and (unless skipped) verifies it.</summary>
    public const string MigrateVerb = "migrate-to-postgres";

    /// <summary>Verifies an already-migrated Postgres against the SQLite it came from.</summary>
    public const string VerifyVerb = "verify-postgres-migration";

    /// <summary>Everything completed and, where run, verification matched.</summary>
    public const int ExitSuccess = 0;

    /// <summary>The command could not run: bad arguments, missing database, or a copy failure.</summary>
    public const int ExitError = 1;

    /// <summary>The copy ran but verification found a difference. Do not cut over.</summary>
    public const int ExitVerificationFailed = 2;

    /// <summary>True when argv selects one of the migration modes instead of the web host.</summary>
    public static bool IsMigrationVerb(string[] args) =>
        args is { Length: > 0 }
        && (string.Equals(args[0], MigrateVerb, StringComparison.Ordinal)
            || string.Equals(args[0], VerifyVerb, StringComparison.Ordinal));

    /// <summary>Runs the selected mode and returns the process exit code.</summary>
    public static async Task<int> RunAsync(
        string[] args,
        IConfiguration configuration,
        ILoggerFactory loggerFactory,
        TimeProvider time,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(loggerFactory);
        ArgumentNullException.ThrowIfNull(time);

        var logger = loggerFactory.CreateLogger("Dependably.Migration");

        MigrationCommandArguments parsed;
        try
        {
            parsed = MigrationCommandArguments.Parse(args, configuration);
        }
        catch (MetadataMigrationException ex)
        {
            logger.LogError("{Message}", ex.Message);
            LogUsage(logger);
            return ExitError;
        }

        if (!File.Exists(parsed.SourcePath))
        {
            logger.LogError(
                "No SQLite database at {SourcePath}. Pass --source, or set DB_PATH to the file to migrate.",
                parsed.SourcePath);
            return ExitError;
        }

        var source = new SqliteMetadataStore(SourceConnectionString(parsed.SourcePath));
        var target = new NpgsqlMetadataStore(parsed.TargetConnectionString);
        var migrator = new SqliteToPostgresMigrator(
            source, target, loggerFactory.CreateLogger<SqliteToPostgresMigrator>());

        try
        {
            if (parsed.Verb == VerifyVerb)
            {
                var report = await migrator.VerifyAsync(ct);
                return report.Ok ? ExitSuccess : ExitVerificationFailed;
            }

            await WarnOnLiveWriterAsync(source, time, logger, ct);

            var result = await migrator.MigrateAsync(
                new MetadataMigrationOptions { Force = parsed.Force, SkipVerification = parsed.SkipVerification },
                ct);

            logger.LogInformation(
                "Migration complete: {Rows} row(s) across {TableCount} table(s); {SkippedCount} source table(s) " +
                "skipped; {SequenceCount} identity sequence(s) reset",
                result.TotalRows, result.Tables.Count, result.SkippedTables.Count, result.ResetSequences.Count);

            if (result.Verification is { Ok: false })
            {
                return ExitVerificationFailed;
            }

            if (result.Verification is null)
            {
                logger.LogWarning(
                    "Verification was skipped. Run `{Verb}` before cutting traffic over to Postgres.", VerifyVerb);
            }

            return ExitSuccess;
        }
        catch (MetadataMigrationException ex)
        {
            logger.LogError("Migration aborted: {Message}", ex.Message);
            return ExitError;
        }
    }

    /// <summary>
    /// The source is opened read-write (the copy never writes to it) but explicitly <em>not</em>
    /// create-on-missing: a typo in <c>--source</c> must fail, not silently migrate a brand-new
    /// empty database over the top of the target.
    /// </summary>
    internal static string SourceConnectionString(string path) =>
        $"Data Source={path};Mode=ReadWrite;Pooling=True";

    /// <summary>
    /// Reports whether a dependably instance still appears to be writing the source. The instance
    /// lock is the natural chokepoint for quiescing writes — a heartbeat younger than the staleness
    /// window means a live node, and a migration taken from underneath one is a torn snapshot.
    /// </summary>
    private static async Task WarnOnLiveWriterAsync(
        IMetadataStore source, TimeProvider time, ILogger logger, CancellationToken ct)
    {
        await using var conn = await source.OpenAsync(ct);

        // xtenant: the instance lock is an instance-global singleton row with no tenant column.
        string? heartbeat = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT heartbeat_at FROM instance_lock WHERE id = @id",
            new { id = InstanceLock.RowId },
            cancellationToken: ct));

        if (string.IsNullOrEmpty(heartbeat)
            || !DateTimeOffset.TryParse(
                heartbeat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var beat))
        {
            return;
        }

        var age = time.GetUtcNow() - beat;
        if (age < TimeSpan.FromSeconds(InstanceLock.DefaultStaleSeconds))
        {
            logger.LogWarning(
                "The source database still carries a fresh instance-lock heartbeat ({AgeSeconds:F0}s old). " +
                "A dependably node is very likely still writing it — stop every node before migrating, or the " +
                "copy is a torn snapshot.",
                age.TotalSeconds);
        }
    }

    private static void LogUsage(ILogger logger) =>
        logger.LogInformation(
            "Usage:\n" +
            "  Dependably {MigrateVerb} [--source <sqlite-path>] [--target <postgres-conn>] [--force] [--skip-verify]\n" +
            "  Dependably {VerifyVerb} [--source <sqlite-path>] [--target <postgres-conn>]\n" +
            "\n" +
            "  --source       Path to the SQLite database. Defaults to DB_PATH.\n" +
            "  --target       Postgres connection string. Defaults to DB_CONNECTION_STRING.\n" +
            "  --force        Replace data already present in the target. Destructive.\n" +
            "  --skip-verify  Copy without the verification pass (run {VerifyVerb} separately).",
            MigrateVerb, VerifyVerb, VerifyVerb);

    private sealed record MigrationCommandArguments(
        string Verb, string SourcePath, string TargetConnectionString, bool Force, bool SkipVerification)
    {
        public static MigrationCommandArguments Parse(string[] args, IConfiguration configuration)
        {
            string verb = args[0];
            string? sourcePath = null;
            string? target = null;
            bool force = false;
            bool skipVerification = false;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--source":
                        sourcePath = ReadOptionValue(args, ref i);
                        break;
                    case "--target":
                        target = ReadOptionValue(args, ref i);
                        break;
                    case "--force":
                        force = true;
                        break;
                    case "--skip-verify":
                        skipVerification = true;
                        break;
                    default:
                        throw new MetadataMigrationException($"Unrecognised option '{args[i]}'.");
                }
            }

            string resolvedSource = Require(
                sourcePath ?? configuration["DB_PATH"],
                "No SQLite source. Pass --source <path> or set DB_PATH.");
            string resolvedTarget = Require(
                target ?? configuration["DB_CONNECTION_STRING"],
                "No Postgres target. Pass --target <connection-string> or set DB_CONNECTION_STRING.");

            return verb == VerifyVerb && (force || skipVerification)
                ? throw new MetadataMigrationException(
                    $"--force and --skip-verify are not valid for {VerifyVerb}; it only reads.")
                : new MigrationCommandArguments(verb, resolvedSource, resolvedTarget, force, skipVerification);
        }

        private static string Require(string? value, string message) =>
            string.IsNullOrWhiteSpace(value) ? throw new MetadataMigrationException(message) : value;

        private static string ReadOptionValue(string[] args, ref int index) =>
            index + 1 >= args.Length
                ? throw new MetadataMigrationException($"Option '{args[index]}' needs a value.")
                : args[++index];
    }
}
