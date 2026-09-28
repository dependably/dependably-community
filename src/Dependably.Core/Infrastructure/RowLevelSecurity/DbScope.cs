namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>
/// Declares, for a block of work outside a request, which tenant its database connections bind
/// to under Postgres row-level security. Background jobs, channel consumers and startup code open
/// connections through shared repositories that take no scope parameter; the job states its scope
/// once, at its entry point, and every <c>OpenAsync</c> inside the block honours it:
///
/// <code>
///   foreach (string orgId in orgIds)
///   {
///       using (DbScope.ForOrg(orgId))
///       {
///           await RunForOrgAsync(orgId, ct);
///       }
///   }
/// </code>
///
/// <para>An explicit scope wins over the request's ambient tenant, so a request-path helper that is
/// cross-tenant by design (a shared-blob reference count) can declare it too. The value is
/// async-local: it flows into awaits and child tasks started inside the block and ends with it.
/// <see cref="CrossTenant"/> is the row-level security bypass, held to the same rule as
/// <c>OpenCrossTenantAsync</c>: an <c>// xtenant: &lt;reason&gt;</c> marker on every call and a pinned
/// call count (<c>CrossTenantOpenComplianceTests</c>).</para>
///
/// <para>Providers without row-level security ignore the scope entirely.</para>
/// </summary>
public static class DbScope
{
    private static readonly AsyncLocal<AmbientTenant?> Current = new();

    /// <summary>The explicitly declared scope of the current flow, or null when none is declared.</summary>
    public static AmbientTenant? Declared => Current.Value;

    /// <summary>Binds connections opened inside the block to <paramref name="orgId"/>.</summary>
    public static IDisposable ForOrg(string orgId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orgId);
        return Push(new AmbientTenant(AmbientTenantKind.Tenant, orgId));
    }

    /// <summary>Opens connections inside the block as the owner, which row-level security does not restrict.</summary>
    public static IDisposable CrossTenant(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return Push(new AmbientTenant(AmbientTenantKind.Apex, null));
    }

    private static Restore Push(AmbientTenant scope)
    {
        var previous = Current.Value;
        Current.Value = scope;
        return new Restore(previous);
    }

    private sealed class Restore(AmbientTenant? previous) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            Current.Value = previous;
        }
    }
}
