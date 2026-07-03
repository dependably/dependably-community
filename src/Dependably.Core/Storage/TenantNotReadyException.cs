namespace Dependably.Storage;

/// <summary>
/// Classified reason a tenant is not ready for registry writes. The HTTP boundary
/// middleware (<c>TenantNotReadyExceptionMiddleware</c>) keys off this enum so the
/// mapping is structured rather than parsed from a free-form string.
/// </summary>
public enum TenantNotReadyReason
{
    /// <summary>No <c>orgs</c> row for the tenant id. Maps to 404.</summary>
    NotFound,
    /// <summary><c>orgs.status</c> is suspended, archived, or deleting. Maps to 423 Locked.</summary>
    StatusInactive,
    /// <summary><c>tenant_provisioning_jobs.state = 'creating'</c>. Maps to 503 + Retry-After.</summary>
    ProvisioningPending,
    /// <summary><c>tenant_provisioning_jobs.state = 'failed'</c>. Maps to 503 + Retry-After.</summary>
    ProvisioningFailed,
}

/// <summary>
/// Raised by <see cref="ITenantStorageResolver.GetRegistryAsync"/> when a tenant is not
/// in a state that admits registry writes. The HTTP mapping lives in
/// <c>TenantNotReadyExceptionMiddleware</c>: NotFound→404, StatusInactive→423 Locked,
/// ProvisioningPending / ProvisioningFailed → 503 with Retry-After.
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
