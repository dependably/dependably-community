using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;
using Npgsql;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A throwaway Postgres database for one integration test host, owned by a non-superuser
/// <c>CREATEROLE</c> role — the shape of an RDS/Aurora master user. The owner is deliberately not a
/// superuser: superusers skip row-level security entirely, so a suite connected as one would pass
/// every isolation assertion for the wrong reason.
///
/// <para>Building the full schema per host is what makes a Postgres run slow, so the process builds
/// it once into a template database — owned by a run-scoped owner role, with the run's RLS role
/// already installed — and each host clones it with <c>CREATE DATABASE … TEMPLATE</c>, a file copy.
/// The host's own boot still runs <c>SchemaInitializer</c>, against a schema that is already
/// converged. The roles and template are dropped when the process exits.</para>
/// </summary>
public sealed class PostgresTestDatabase : IAsyncDisposable
{
    private const string OwnerPassword = "pg_test_owner_pw";

    private static readonly SemaphoreSlim CloneGate = new(1, 1);
    private static readonly Lazy<Task<RunTemplate>> Template = new(CreateTemplateAsync);

    private PostgresTestDatabase(RunTemplate template, string databaseName)
    {
        DatabaseName = databaseName;
        OwnerRole = template.OwnerRole;
        RlsRole = template.RlsRole;
        OwnerConnectionString = template.ConnectionStringFor(databaseName);
    }

    public string DatabaseName { get; }

    public string OwnerRole { get; }

    public string RlsRole { get; }

    public string OwnerConnectionString { get; }

    // Creating and dropping databases is I/O-bound and slows sharply on a loaded CI runner; the
    // default 30 s command timeout is too tight for it. These statements are harness-only.
    internal const int AdminCommandTimeoutSeconds = 300;

    public static string SuperuserConnectionString =>
        new NpgsqlConnectionStringBuilder(
            Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
            ?? throw new InvalidOperationException(
                "TEST_POSTGRES_CONNECTION must be set to run tests against Postgres."))
        {
            CommandTimeout = AdminCommandTimeoutSeconds,
        }.ConnectionString;

    public static async Task<PostgresTestDatabase> CreateAsync()
    {
        var template = await Template.Value;
        string name = "pgt_db_" + Guid.NewGuid().ToString("N")[..12];

        // Postgres refuses to copy a template another session is copying or connected to.
        await CloneGate.WaitAsync();
        try
        {
            await using var conn = new NpgsqlConnection(SuperuserConnectionString);
            await conn.OpenAsync();
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"CREATE DATABASE {name} TEMPLATE {template.DatabaseName} OWNER {template.OwnerRole}");
        }
        finally
        {
            CloneGate.Release();
        }

        return new PostgresTestDatabase(template, name);
    }

    // Best effort: a database that fails to drop here is still owned by the run's owner role, and
    // the process-exit sweep drops every database that role owns. Cleanup never fails a test.
    public async ValueTask DisposeAsync()
    {
        NpgsqlConnection.ClearPool(new NpgsqlConnection(OwnerConnectionString));
        try
        {
            await using var conn = new NpgsqlConnection(SuperuserConnectionString);
            await conn.OpenAsync();
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP DATABASE IF EXISTS {DatabaseName} WITH (FORCE)");
        }
        catch (NpgsqlException)
        {
            // Left for the process-exit sweep.
        }
    }

    // A run older than this is abandoned — no test run lasts hours — so the next run may reclaim it
    // without touching one that is still going.
    private static readonly TimeSpan AbandonedRunAge = TimeSpan.FromHours(6);

    private static async Task<RunTemplate> CreateTemplateAsync()
    {
        // The run id leads with its creation time so an abandoned run can be recognised by age: the
        // process-exit sweep does not always get to finish before the test host is torn down.
        var now = TimeProvider.System.GetUtcNow();
        string run = now.ToString("yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture)
            + "_" + Guid.NewGuid().ToString("N")[..8];
        var template = new RunTemplate("pgt_tmpl_" + run, "pgt_owner_" + run, "pgt_rls_" + run);
        await ReclaimAbandonedRunsAsync(now);

        await using (var conn = new NpgsqlConnection(SuperuserConnectionString))
        {
            await conn.OpenAsync();
            // rawsql: identifiers are fixed prefixes plus a Guid suffix; the password is a constant.
            await conn.ExecuteAsync($"CREATE ROLE {template.OwnerRole} LOGIN CREATEROLE PASSWORD '{OwnerPassword}'");
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"CREATE DATABASE {template.DatabaseName} OWNER {template.OwnerRole}");
        }

        await using (var conn = new NpgsqlConnection(
            new NpgsqlConnectionStringBuilder(SuperuserConnectionString)
            {
                Database = template.DatabaseName,
                Pooling = false,
            }.ConnectionString))
        {
            await conn.OpenAsync();
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"ALTER SCHEMA public OWNER TO {template.OwnerRole}");
        }

        // Install the schema, the RLS role and its policies once; every clone inherits them.
        string templateConnection = template.ConnectionStringFor(template.DatabaseName);
        var options = new RowLevelSecurityOptions(RowLevelSecurityMode.Enforce, template.RlsRole) { Explicit = true };
        await new SchemaInitializer(new NpgsqlMetadataStore(templateConnection, options, null)).InitializeAsync();
        NpgsqlConnection.ClearPool(new NpgsqlConnection(templateConnection));

        AppDomain.CurrentDomain.ProcessExit += (_, _) => template.DropAsync().GetAwaiter().GetResult();
        return template;
    }

    private static async Task ReclaimAbandonedRunsAsync(DateTimeOffset now)
    {
        await using var conn = new NpgsqlConnection(SuperuserConnectionString);
        await conn.OpenAsync();
        var owners = await conn.QueryAsync<string>(
            "SELECT rolname FROM pg_roles WHERE rolname LIKE 'pgt\\_owner\\_%'");
        foreach (string owner in owners)
        {
            string run = owner["pgt_owner_".Length..];
            if (run.Length < 12
                || !DateTimeOffset.TryParseExact(
                    run[..12], "yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var created)
                || now - created < AbandonedRunAge)
            {
                continue;
            }

            try
            {
                await new RunTemplate("pgt_tmpl_" + run, owner, "pgt_rls_" + run).DropAsync();
            }
            catch (NpgsqlException)
            {
                // Another run reclaiming the same leftovers; whichever finishes, they go.
            }
        }
    }

    private sealed record RunTemplate(string DatabaseName, string OwnerRole, string RlsRole)
    {
        public string ConnectionStringFor(string database) =>
            new NpgsqlConnectionStringBuilder(SuperuserConnectionString)
            {
                Database = database,
                Username = OwnerRole,
                Password = OwnerPassword,
            }.ConnectionString;

        public async Task DropAsync()
        {
            NpgsqlConnection.ClearAllPools();
            await using var conn = new NpgsqlConnection(SuperuserConnectionString);
            await conn.OpenAsync();
            // Any host database a crashed test failed to drop still belongs to this run.
            var leftovers = await conn.QueryAsync<string>(
                "SELECT datname FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = @owner)",
                new { owner = OwnerRole });
            foreach (string database in leftovers)
            {
                // rawsql: database names come from pg_database rows owned by this run's role.
                await conn.ExecuteAsync($"DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)");
            }

            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP ROLE IF EXISTS {RlsRole}");
            // rawsql: identifiers are fixed prefixes plus a Guid suffix.
            await conn.ExecuteAsync($"DROP ROLE IF EXISTS {OwnerRole}");
        }
    }
}
