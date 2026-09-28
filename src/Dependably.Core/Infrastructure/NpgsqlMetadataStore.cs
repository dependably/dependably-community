using System.Data.Common;
using Dependably.Infrastructure.RowLevelSecurity;
using Npgsql;

namespace Dependably.Infrastructure;

/// <summary>
/// Postgres metadata store. With <see cref="RowLevelSecurityMode.Off"/> every connection is a plain
/// pooled connection as the connecting role. With <see cref="RowLevelSecurityMode.Enforce"/> every
/// open — tenant, no-tenant, and cross-tenant alike — first writes the session's role and tenant
/// in one round trip, so a pooled connection never serves a lease with the previous lease's
/// identity, whatever the pool's reset behaviour (<see cref="PostgresRowLevelSecurityInstaller"/>).
/// </summary>
public sealed class NpgsqlMetadataStore : IMetadataStore
{
    // set_config rather than SET ROLE so both values bind as parameters. 'none' is SET ROLE NONE:
    // back to the connecting (owner) role.
    private const string BindSessionSql =
        "SELECT set_config('role', @role, false), " +
        "set_config('dependably.org_id', CASE WHEN @orgId = '' THEN '' ELSE pg_backend_pid()::text || ':' || @orgId END, false)";

    private const string OwnerRole = "none";

    private readonly string _connectionString;
    private readonly IAmbientTenantScope? _ambient;

    public NpgsqlMetadataStore(string connectionString)
        : this(connectionString, RowLevelSecurityOptions.Disabled, null)
    {
    }

    public NpgsqlMetadataStore(
        string connectionString, RowLevelSecurityOptions rowLevelSecurity, IAmbientTenantScope? ambient)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        ArgumentNullException.ThrowIfNull(rowLevelSecurity);

        _connectionString = connectionString;
        _rowLevelSecurity = rowLevelSecurity;
        _ambient = ambient;

        if (rowLevelSecurity.Enforced && new NpgsqlConnectionStringBuilder(connectionString).Multiplexing)
        {
            // Multiplexing interleaves commands from many callers on shared physical connections,
            // so a session-level role and tenant cannot belong to any one caller.
            const string reason = "DB_CONNECTION_STRING sets Multiplexing=true";
            if (rowLevelSecurity.Explicit)
            {
                throw new InvalidOperationException(
                    $"{RowLevelSecurityOptions.ModeKey}=enforce cannot be combined with Multiplexing=true in DB_CONNECTION_STRING.");
            }

            FallBackToOwnerSessions(reason);
        }
    }

    public DbProvider Provider => DbProvider.Postgres;

    private volatile RowLevelSecurityOptions _rowLevelSecurity;

    public RowLevelSecurityOptions RowLevelSecurity => _rowLevelSecurity;

    /// <summary>Why a defaulted enforce fell back to owner sessions, or null when it did not.</summary>
    public string? RowLevelSecurityFallbackReason { get; private set; }

    /// <summary>
    /// Turns a defaulted <c>enforce</c> into plain owner sessions because the database cannot
    /// support row-level security. Called only while the host boots, before it serves; an explicit
    /// <c>enforce</c> never reaches here — it fails startup instead.
    /// </summary>
    internal void FallBackToOwnerSessions(string reason)
    {
        RowLevelSecurityFallbackReason = reason;
        _rowLevelSecurity = _rowLevelSecurity with { Mode = RowLevelSecurityMode.Off };
    }

    public Task<DbConnection> OpenAsync(CancellationToken ct = default)
    {
        if (!RowLevelSecurity.Enforced)
        {
            return OpenPlainAsync(ct);
        }

        var ambient = DbScope.Declared ?? _ambient?.Current ?? AmbientTenant.None;
        return ambient.Kind switch
        {
            AmbientTenantKind.Tenant => OpenBoundAsync(RowLevelSecurity.RoleName, ambient.OrgId!, ct),
            AmbientTenantKind.Apex => OpenBoundAsync(OwnerRole, "", ct),
            _ => OpenBoundAsync(RowLevelSecurity.RoleName, "", ct),
        };
    }

    public Task<DbConnection> OpenForTenantAsync(TenantDbScope scope, CancellationToken ct = default)
    {
        string orgId = scope.OrgId
            ?? throw new ArgumentException("An uninitialized TenantDbScope binds no tenant.", nameof(scope));

        return RowLevelSecurity.Enforced
            ? OpenBoundAsync(RowLevelSecurity.RoleName, orgId, ct)
            : OpenPlainAsync(ct);
    }

    public Task<DbConnection> OpenCrossTenantAsync(string reason, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return RowLevelSecurity.Enforced
            ? OpenBoundAsync(OwnerRole, "", ct)
            : OpenPlainAsync(ct);
    }

    private async Task<DbConnection> OpenPlainAsync(CancellationToken ct)
    {
        var conn = new NpgsqlConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }

    private async Task<DbConnection> OpenBoundAsync(string role, string orgId, CancellationToken ct)
    {
        var conn = new NpgsqlConnection(_connectionString);
        try
        {
            await conn.OpenAsync(ct);
            await using var bind = new NpgsqlCommand(BindSessionSql, conn);
            bind.Parameters.AddWithValue("role", role);
            bind.Parameters.AddWithValue("orgId", orgId);
            await bind.ExecuteNonQueryAsync(ct);
        }
        catch
        {
            // Never hand out a connection whose identity did not bind; the next open on this
            // physical connection rewrites both values regardless.
            await conn.DisposeAsync();
            throw;
        }

        return conn;
    }
}
