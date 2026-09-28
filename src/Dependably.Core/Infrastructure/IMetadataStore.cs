using System.Data.Common;
using Dependably.Infrastructure.RowLevelSecurity;

namespace Dependably.Infrastructure;

public enum DbProvider { Sqlite, Postgres }

public interface IMetadataStore
{
    DbProvider Provider { get; }

    /// <summary>
    /// Returns an open connection. Caller is responsible for disposing. Under Postgres row-level
    /// security the connection is bound to the request's resolved tenant, or to no tenant outside a
    /// request (<see cref="IAmbientTenantScope"/>).
    /// </summary>
    Task<DbConnection> OpenAsync(CancellationToken ct = default);

    /// <summary>
    /// Returns an open connection bound to <paramref name="scope"/>. Providers without row-level
    /// security ignore the scope; the application-level <c>org_id</c> filter still applies.
    /// </summary>
    Task<DbConnection> OpenForTenantAsync(TenantDbScope scope, CancellationToken ct = default) => OpenAsync(ct);

    /// <summary>
    /// Returns an open connection that row-level security does not restrict: schema DDL and
    /// migrations, the apex surface, and genuinely cross-tenant sweeps. Each call site carries an
    /// <c>// xtenant: &lt;reason&gt;</c> marker (enforced by <c>CrossTenantOpenComplianceTests</c>)
    /// and passes the same reason here, so the bypass is as visible in review as the marker.
    /// </summary>
    Task<DbConnection> OpenCrossTenantAsync(string reason, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return OpenAsync(ct);
    }
}
