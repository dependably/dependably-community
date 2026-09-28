using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>
/// Installs and verifies the Postgres row-level security backstop. It sits under the
/// application-level <c>WHERE org_id = @orgId</c> filter, which stays the primary isolation layer
/// on both providers; a query that forgets or mis-binds that filter is refused by the database
/// instead of returning another tenant's rows.
///
/// <para><b>Coverage is derived from the live catalogue, not a list.</b> Every base table in the
/// schema carrying an <c>org_id</c> or <c>tenant_id</c> column gets RLS enabled and the
/// <see cref="PolicyName"/> policy, on every boot. A table added by a future schema file or
/// migration is covered without code, and a table recreated by a reshape (which drops its
/// policies) is re-covered on the next boot. <see cref="VerifyAsync"/> then refuses to start if any
/// such table, or any view, is left uncovered.</para>
///
/// <para><b>A missing tenant raises; it never returns zero rows.</b> The policy compares against
/// <c>dependably_current_org()</c>, which raises <see cref="NoTenantContextSqlState"/> when the
/// connection carries no tenant. An empty result would read as "no rule applies" to the blocklist,
/// policy and trust-anchor lookups, and as "nothing to copy" to a migration — a silent fail-open
/// or data loss. The tenant value also records the backend it was set on, and the function raises
/// <see cref="SessionMismatchSqlState"/> when a setting is read on a different backend from the one
/// that wrote it. It cannot catch a transaction-mode connection pooler handing a statement to a
/// backend another client bound — that setting was written on the same backend, so its pid
/// matches — which is why <see cref="ProbeTenantSessionAsync"/> detects such a pool at boot.</para>
///
/// <para><b>Owner bypass is by role, not FORCE.</b> The connecting role owns the tables and is
/// exempt; tenant connections switch to the non-owner <see cref="RowLevelSecurityOptions.RoleName"/>.
/// FORCE would subject the owner too, which breaks <c>COPY FROM</c> (rejected on any table under
/// RLS) in the SQLite-to-Postgres migrator and turns <c>pg_dump</c> into an error. Views are created
/// <c>security_invoker</c> so reading through one applies the reader's policies, not the owner's.</para>
/// </summary>
public static class PostgresRowLevelSecurityInstaller
{
    /// <summary>The per-table policy. A changed expression ships under a new version suffix.</summary>
    public const string PolicyName = "dependably_tenant_isolation_v1";

    /// <summary>The session setting carrying <c>&lt;backend pid&gt;:&lt;org id&gt;</c>.</summary>
    public const string TenantSetting = "dependably.org_id";

    /// <summary>Raised by the policy when the connection carries no tenant.</summary>
    public const string NoTenantContextSqlState = "DR001";

    /// <summary>Raised by the policy when the tenant was set on a different database backend.</summary>
    public const string SessionMismatchSqlState = "DR002";

    /// <summary>Postgres 15 introduced <c>security_invoker</c> views, without which views bypass RLS.</summary>
    public const int MinimumServerVersionNum = 150000;

    // PARALLEL RESTRICTED keeps the call in the leader process: a parallel worker has its own
    // pg_backend_pid(), so evaluating the session check there would raise on every parallel scan.
    // Deliberately not SECURITY DEFINER — it reads only the caller's own session state.
    private const string CurrentOrgFunctionSql = """
        CREATE OR REPLACE FUNCTION dependably_current_org() RETURNS text
        LANGUAGE plpgsql STABLE PARALLEL RESTRICTED AS $fn$
        DECLARE
          raw text := current_setting('dependably.org_id', true);
          sep int;
        BEGIN
          IF raw IS NULL OR raw = '' THEN
            RAISE EXCEPTION 'row-level security: this connection carries no tenant'
              USING ERRCODE = 'DR001';
          END IF;
          sep := strpos(raw, ':');
          IF sep = 0 OR left(raw, sep - 1) <> pg_backend_pid()::text THEN
            RAISE EXCEPTION 'row-level security: the tenant was set on a different database session'
              USING ERRCODE = 'DR002';
          END IF;
          RETURN substr(raw, sep + 1);
        END
        $fn$
        """;

    // The role and policy names reach the DO block through session settings because a DO block
    // takes no bind parameters; every identifier is quoted with format('%I').
    private const string ApplySql = """
        DO $do$
        DECLARE
          rls_role text := current_setting('dependably.rls_apply_role');
          policy_name text := current_setting('dependably.rls_apply_policy');
          schema_name text := current_schema();
          r record;
          stale record;
          expr text;
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = rls_role) THEN
            BEGIN
              EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', rls_role);
            EXCEPTION WHEN duplicate_object THEN NULL;
            END;
          END IF;

          IF NOT pg_has_role(current_user, rls_role,
                 CASE WHEN current_setting('server_version_num')::int >= 160000 THEN 'SET' ELSE 'MEMBER' END) THEN
            EXECUTE format('GRANT %I TO CURRENT_USER', rls_role);
          END IF;

          EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', schema_name, rls_role);
          EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I', schema_name, rls_role);
          EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO %I', schema_name, rls_role);
          EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', schema_name, rls_role);
          EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I', schema_name, rls_role);

          FOR r IN
            SELECT DISTINCT ON (c.oid) c.oid::regclass AS rel, a.attname AS col, c.relrowsecurity AS enabled
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_attribute a ON a.attrelid = c.oid AND NOT a.attisdropped AND a.attname IN ('org_id', 'tenant_id')
            WHERE n.nspname = schema_name AND c.relkind IN ('r', 'p')
            ORDER BY c.oid, a.attname
          LOOP
            expr := format('%I = (SELECT dependably_current_org())', r.col);
            IF NOT r.enabled THEN
              EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', r.rel);
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = r.rel AND p.polname = policy_name) THEN
              EXECUTE format('CREATE POLICY %I ON %s USING (%s) WITH CHECK (%s)', policy_name, r.rel, expr, expr);
            END IF;
            FOR stale IN
              SELECT p.polname FROM pg_policy p
              WHERE p.polrelid = r.rel AND p.polname LIKE 'dependably\_tenant\_isolation%' AND p.polname <> policy_name
            LOOP
              EXECUTE format('DROP POLICY %I ON %s', stale.polname, r.rel);
            END LOOP;
          END LOOP;
        END
        $do$
        """;

    /// <summary>
    /// Creates the policy function and the RLS role, grants the role the schema's tables, and
    /// enables RLS plus the policy on every tenant-scoped table. Idempotent, and cheap on a
    /// converged database: a table already covered takes no DDL lock. Runs on the owner
    /// connection, inside the schema migration lock.
    /// </summary>
    /// <summary>
    /// Tenant data with no tenant column of its own, covered through its parent row: a version is
    /// visible when its package is, a version's child rows when the version is. Each predicate
    /// queries a parent that is itself under row-level security, so the tenant check — and the
    /// raise on a missing tenant — is the parent's. The child tables also hold the global proxy
    /// plane's rows (<c>cache_artifact_id</c> set, no version), which belong to no tenant and stay
    /// visible, exactly as <c>cache_artifact</c> is.
    /// </summary>
    public static readonly IReadOnlyList<(string Table, string Predicate)> ParentScopedTables =
    [
        ("package_versions",
            "EXISTS (SELECT 1 FROM packages p WHERE p.id = package_versions.package_id AND p.org_id = (SELECT dependably_current_org()))"),
        ("package_version_vulns",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = package_version_vulns.package_version_id)"),
        ("package_version_licenses",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = package_version_licenses.package_version_id)"),
        ("rpm_metadata",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = rpm_metadata.package_version_id)"),
        ("maven_version_files",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = maven_version_files.package_version_id)"),
        ("cargo_metadata",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = cargo_metadata.version_id)"),
        ("hex_release",
            "cache_artifact_id IS NOT NULL OR EXISTS (SELECT 1 FROM package_versions v WHERE v.id = hex_release.version_id)"),
        ("sbom_component_vulns",
            "EXISTS (SELECT 1 FROM sbom_components c WHERE c.id = sbom_component_vulns.component_id)"),
        ("banner_dismissals",
            "EXISTS (SELECT 1 FROM users u WHERE u.id = banner_dismissals.user_id)"),
    ];

    public static Task ApplyAsync(DbConnection ownerConnection, RowLevelSecurityOptions options)
    {
        ArgumentNullException.ThrowIfNull(ownerConnection);
        ArgumentNullException.ThrowIfNull(options);
        return ApplyCoreAsync(ownerConnection, options);
    }

    private static async Task ApplyCoreAsync(DbConnection ownerConnection, RowLevelSecurityOptions options)
    {
        await ownerConnection.ExecuteAsync(CurrentOrgFunctionSql);
        await ownerConnection.ExecuteAsync(
            "SELECT set_config('dependably.rls_apply_role', @role, false), set_config('dependably.rls_apply_policy', @policy, false)",
            new { role = options.RoleName, policy = PolicyName });
        try
        {
            await ownerConnection.ExecuteAsync(ApplySql);
            await ApplyParentScopedPoliciesAsync(ownerConnection);
        }
        finally
        {
            await ownerConnection.ExecuteAsync(
                "SELECT set_config('dependably.rls_apply_role', '', false), set_config('dependably.rls_apply_policy', '', false)");
        }
    }

    // Same shape as the catalogue-derived pass: enable where not yet enabled and create the policy
    // where missing, so a converged database takes no DDL lock.
    private static async Task ApplyParentScopedPoliciesAsync(DbConnection ownerConnection)
    {
        foreach ((string table, string predicate) in ParentScopedTables)
        {
            var state = await ownerConnection.QuerySingleOrDefaultAsync<(bool Enabled, bool HasPolicy)?>(
                """
                SELECT c.relrowsecurity,
                       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = @policy)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = current_schema() AND c.relname = @table AND c.relkind IN ('r', 'p')
                """,
                new { table, policy = PolicyName });
            if (state is null)
            {
                continue;
            }

            if (!state.Value.Enabled)
            {
                // rawsql: table comes from ParentScopedTables, a compile-time constant list.
                await ownerConnection.ExecuteAsync($"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY");
            }

            if (!state.Value.HasPolicy)
            {
                // rawsql: table, policy name and predicate come from compile-time constants.
                await ownerConnection.ExecuteAsync(
                    $"CREATE POLICY {PolicyName} ON {table} USING ({predicate}) WITH CHECK ({predicate})");
            }
        }
    }

    /// <summary>
    /// Returns every reason the backstop would not hold on this database, or an empty list. Read on
    /// the owner connection after <see cref="ApplyAsync"/>.
    /// </summary>
    public static Task<IReadOnlyList<string>> FindProblemsAsync(
        DbConnection ownerConnection, RowLevelSecurityOptions options)
    {
        ArgumentNullException.ThrowIfNull(ownerConnection);
        ArgumentNullException.ThrowIfNull(options);
        return FindProblemsCoreAsync(ownerConnection, options);
    }

    private static async Task<IReadOnlyList<string>> FindProblemsCoreAsync(
        DbConnection ownerConnection, RowLevelSecurityOptions options)
    {
        var problems = new List<string>();

        int version = await ownerConnection.ExecuteScalarAsync<int>("SELECT current_setting('server_version_num')::int");
        if (version < MinimumServerVersionNum)
        {
            problems.Add(
                $"Postgres server_version_num {version} is below {MinimumServerVersionNum}; views cannot be security_invoker, so they would read every tenant.");
        }

        var role = await ownerConnection.QuerySingleOrDefaultAsync<(bool Super, bool Bypass)?>(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = @role", new { role = options.RoleName });
        if (role is null)
        {
            problems.Add($"Role '{options.RoleName}' does not exist.");
        }
        else if (role.Value.Super || role.Value.Bypass)
        {
            problems.Add($"Role '{options.RoleName}' is a superuser or has BYPASSRLS, so row-level security never applies to it.");
        }

        bool inheritsOwner = await ownerConnection.ExecuteScalarAsync<bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = @role) AND pg_has_role(@role, session_user, 'MEMBER')",
            new { role = options.RoleName });
        if (inheritsOwner)
        {
            problems.Add(
                $"Role '{options.RoleName}' is a member of the owner role, so it holds the owner's exemption from row-level security.");
        }

        var uncovered = await ownerConnection.QueryAsync<string>(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema()
              AND c.relkind IN ('r', 'p')
              AND EXISTS (
                SELECT 1 FROM pg_attribute a
                WHERE a.attrelid = c.oid AND NOT a.attisdropped AND a.attname IN ('org_id', 'tenant_id'))
              AND (NOT c.relrowsecurity
                   OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = @policy))
            ORDER BY c.relname
            """,
            new { policy = PolicyName });
        problems.AddRange(uncovered.Select(t => $"Tenant table '{t}' has no row-level security policy."));

        string[] parentScoped = ParentScopedTables.Select(t => t.Table).ToArray();
        var uncoveredChildren = await ownerConnection.QueryAsync<string>(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema()
              AND c.relname = ANY(@tables)
              AND (NOT c.relrowsecurity
                   OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = @policy))
            ORDER BY c.relname
            """,
            new { tables = parentScoped, policy = PolicyName });
        problems.AddRange(uncoveredChildren.Select(t => $"Parent-scoped table '{t}' has no row-level security policy."));

        // A plain view runs with its owner's rights and so reads every tenant; a materialized view
        // stores rows computed as the owner and cannot be security_invoker at all.
        var unsafeViews = await ownerConnection.QueryAsync<string>(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = current_schema()
              AND (c.relkind = 'm'
                   OR (c.relkind = 'v' AND NOT COALESCE('security_invoker=true' = ANY (c.reloptions), false)))
            ORDER BY c.relname
            """);
        problems.AddRange(unsafeViews.Select(v => $"View '{v}' is not security_invoker, so it bypasses row-level security."));

        return problems;
    }

    // Several connections held open at once is what separates a pooler from a direct connection:
    // one connection on one backend is always self-consistent. The boot holds this many tenant
    // connections plus the owner connection while it probes, so a multi-tenant deployment needs a
    // MaxPoolSize of at least ProbeConnections + 1.
    private const int ProbeConnections = 3;

    private const string SessionReadSql = """
        SELECT pg_backend_pid(), current_setting(@setting, true), current_user::text, r.rolsuper, r.rolbypassrls
        FROM pg_roles r
        WHERE r.rolname = current_user
        """;

    private const string PoolerSentence =
        "statements are not staying on one session, which is what a transaction-mode pooler "
        + "(PgBouncer pool_mode=transaction) does between statements. Row-level security cannot run over it; "
        + "use a session-mode pool or a direct connection.";

    /// <summary>One read of a probe connection's session state, taken as its own statement.</summary>
    internal readonly record struct SessionReading(
        int Connection, int Pass, string ExpectedOrg, int BackendPid, string? Tenant, string User, bool Super, bool Bypass);

    /// <summary>
    /// Opens several tenant connections through <paramref name="store"/> at once, each bound to its
    /// own tenant, and reads each one back twice as separate statements. It checks that every
    /// connection runs as the RLS role, which is neither superuser nor BYPASSRLS — a misconfigured
    /// role makes every other check pass while the policies are skipped — and that each keeps its
    /// database backend and its own tenant from one statement to the next. A transaction-mode
    /// pooler reassigns the backend between statements, so a connection reads back a tenant
    /// another client bound, on the backend that wrote it; <see cref="SessionMismatchSqlState"/>
    /// never raises on that, so it is detected here and reported like any other reason the
    /// backstop cannot hold.
    /// </summary>
    public static Task<IReadOnlyList<string>> ProbeTenantSessionAsync(
        IMetadataStore store, RowLevelSecurityOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(options);
        return ProbeTenantSessionCoreAsync(store, options, ct);
    }

    private static async Task<IReadOnlyList<string>> ProbeTenantSessionCoreAsync(
        IMetadataStore store, RowLevelSecurityOptions options, CancellationToken ct)
    {
        var connections = new List<DbConnection>(ProbeConnections);
        try
        {
            // Each open binds as its own statement, which is the unit a transaction pooler reassigns.
            for (int i = 1; i <= ProbeConnections; i++)
            {
                connections.Add(await store.OpenForTenantAsync(TenantDbScope.ForOrgIteration(ProbeOrg(i)), ct));
            }

            // Every read is its own implicit transaction. The second pass runs in reverse so a
            // round-robin pool the size of the probe cannot hand each connection its own backend
            // back by coincidence.
            var readings = new List<SessionReading>(ProbeConnections * 2);
            for (int i = 0; i < ProbeConnections; i++)
            {
                readings.Add(await ReadSessionAsync(connections[i], i + 1, pass: 1, ct));
            }

            for (int i = ProbeConnections - 1; i >= 0; i--)
            {
                readings.Add(await ReadSessionAsync(connections[i], i + 1, pass: 2, ct));
            }

            return FindSessionProblems(readings, options);
        }
        finally
        {
            foreach (var conn in connections)
            {
                await conn.DisposeAsync();
            }
        }
    }

    private static string ProbeOrg(int connection) => $"rls-probe-{connection}";

    private static async Task<SessionReading> ReadSessionAsync(
        DbConnection conn, int connection, int pass, CancellationToken ct)
    {
        var row = await conn.QuerySingleAsync<(int Pid, string? Tenant, string User, bool Super, bool Bypass)>(
            new CommandDefinition(SessionReadSql, new { setting = TenantSetting }, cancellationToken: ct));
        return new SessionReading(
            connection, pass, ProbeOrg(connection), row.Pid, row.Tenant, row.User, row.Super, row.Bypass);
    }

    /// <summary>
    /// Every reason the probe readings show the backstop would not hold, each kind reported once.
    /// Only values the server returned are judged: a failed read raises instead, so a dropped
    /// backend is never mistaken for a pooler.
    /// </summary>
    internal static IReadOnlyList<string> FindSessionProblems(
        IReadOnlyList<SessionReading> readings, RowLevelSecurityOptions options)
    {
        ArgumentNullException.ThrowIfNull(readings);
        ArgumentNullException.ThrowIfNull(options);

        var problems = new List<string>();
        string? tenantDrift = null;
        foreach (var reading in readings)
        {
            if (!string.Equals(reading.User, options.RoleName, StringComparison.Ordinal))
            {
                problems.Add($"A tenant connection runs as '{reading.User}', not '{options.RoleName}'.");
            }

            if (reading.Super || reading.Bypass)
            {
                problems.Add($"A tenant connection runs as '{reading.User}', which is a superuser or has BYPASSRLS.");
            }

            // The setting is <backend pid>:<org>. Comparing the whole value catches both a backend
            // another client bound and a backend whose setting was reset.
            string expected = $"{reading.BackendPid}:{reading.ExpectedOrg}";
            if (tenantDrift is null && !string.Equals(reading.Tenant, expected, StringComparison.Ordinal))
            {
                string seen = string.IsNullOrEmpty(reading.Tenant) ? "<none>" : reading.Tenant;
                tenantDrift =
                    $"A tenant connection bound to '{reading.ExpectedOrg}' read back tenant '{seen}' on backend "
                    + $"{reading.BackendPid}: {PoolerSentence}";
            }
        }

        if (tenantDrift is not null)
        {
            problems.Add(tenantDrift);
        }

        int[]? backendChange = readings
            .GroupBy(r => r.Connection)
            .Select(g => g.OrderBy(r => r.Pass).Select(r => r.BackendPid).Distinct().ToArray())
            .FirstOrDefault(pids => pids.Length > 1);
        if (backendChange is not null)
        {
            problems.Add(
                $"A tenant connection changed database backend between two statements (pid {backendChange[0]} then "
                + $"{backendChange[1]}): {PoolerSentence}");
        }

        return problems.Distinct(StringComparer.Ordinal).ToList();
    }
}
