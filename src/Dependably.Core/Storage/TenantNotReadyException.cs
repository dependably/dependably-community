namespace Dependably.Storage;

/// <summary>
/// Classified reason a tenant is not ready to be served. <c>TenantNotReadyResponseWriter</c>
/// keys off this enum so the mapping is structured rather than parsed from a free-form string.
///
/// <para>
/// Each reason maps to two different wire shapes, because docker/OCI clients do not parse
/// RFC 7807. On <c>/v2/</c> routes the response is an OCI Distribution Spec error envelope; on
/// every other route it is problem JSON. The status codes differ too — do not read the
/// problem-JSON column as "the" mapping.
/// </para>
/// </summary>
public enum TenantNotReadyReason
{
    /// <summary>No <c>orgs</c> row for the tenant id. 404 both ways (OCI: <c>NAME_UNKNOWN</c>).</summary>
    NotFound,
    /// <summary>
    /// <c>orgs.status</c> is suspended, archived, or deleting. 423 Locked as problem JSON,
    /// but <b>403 with OCI code <c>DENIED</c></b> on <c>/v2/</c> — the one reason whose status
    /// code differs by surface.
    /// </summary>
    StatusInactive,
    /// <summary>
    /// <c>tenant_provisioning_jobs.state = 'creating'</c>. 503 both ways; <c>Retry-After</c> is
    /// set on the problem-JSON path only (OCI: <c>UNAVAILABLE</c>, no <c>Retry-After</c>).
    /// </summary>
    ProvisioningPending,
    /// <summary>
    /// <c>tenant_provisioning_jobs.state = 'failed'</c>. 503 both ways; <c>Retry-After</c> is
    /// set on the problem-JSON path only (OCI: <c>UNAVAILABLE</c>, no <c>Retry-After</c>).
    /// </summary>
    ProvisioningFailed,
}

/// <summary>
/// Raised by <see cref="ITenantStorageResolver.GetRegistryAsync"/> when a tenant is not
/// in a state that admits registry writes, and translated at the HTTP boundary by
/// <c>TenantNotReadyExceptionMiddleware</c>. It is not the only way a caller meets these
/// reasons: <c>TenantStatusEnforcementMiddleware</c> refuses a non-active tenant far earlier
/// and writes the same shapes directly, without raising this exception. Both go through
/// <c>TenantNotReadyResponseWriter</c>, which owns the mapping — see
/// <see cref="TenantNotReadyReason"/> for the per-surface status codes.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public sealed class TenantNotReadyException : Exception
{
    public string TenantId { get; }
    public TenantNotReadyReason Reason { get; }
    public string Detail { get; }

    public TenantNotReadyException(string tenantId, TenantNotReadyReason reason, string detail)
        : base($"Tenant '{tenantId}' is not ready for registry writes: {detail}")
    {
        TenantId = tenantId;
        Reason = reason;
        Detail = detail;
    }
}
