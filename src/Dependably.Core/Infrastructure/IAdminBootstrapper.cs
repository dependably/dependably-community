using System.Data.Common;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure;

/// <summary>
/// Creates the first-boot administrator account for the modes that have one: <c>single</c> (a
/// tenant owner) and <c>multi</c>/<c>header</c> (a system_admin). Both branches hash a password
/// with BCrypt, so the implementation lives with the management wiring — a protocol-only edge
/// host registers no bootstrapper, which makes single/multi bootstrap impossible by construction
/// (the edge branch in <see cref="FirstBootService"/> seeds only a headless cache org and never
/// calls this).
///
/// The methods run inside the first-boot serialized transaction opened by
/// <see cref="FirstBootService"/>; they must not open their own connection or commit.
/// </summary>
public interface IAdminBootstrapper
{
    /// <summary>
    /// <c>single</c> mode: creates one tenant, its settings, seeds the standard public upstreams,
    /// and the bootstrap admin as that tenant's owner (must_change_password = 1).
    /// </summary>
    Task BootstrapSingleAsync(DbConnection conn, IConfiguration config, EnvelopeProtector envelope);

    /// <summary>
    /// <c>multi</c>/<c>header</c> mode: creates only the system_admin. No tenant is auto-created —
    /// tenants are provisioned through the management API.
    /// </summary>
    void BootstrapMulti(DbConnection conn, IConfiguration config);
}
