namespace Dependably.Storage;

/// <summary>
/// Tenant-aware accessor for the two-tier blob storage. Every registry write — anywhere
/// that touches <see cref="BlobKeys.Hosted"/> — must resolve its <see cref="IBlobStore"/>
/// through <see cref="GetRegistryAsync"/> so the gate checks (tenant lifecycle status,
/// async provisioning state) run on the same code path the storage selection runs on.
///
/// In community pool deployments the resolver returns the singleton registry store
/// regardless of <c>tenantId</c>; the gate checks still apply defensively. Enterprise
/// (out of tree) returns per-tenant bucket stores from the <c>tenant_storage</c> table.
///
/// <see cref="Cache"/> is intentionally not tenant-aware: the proxy cache is
/// content-addressed (<c>proxy/{sha256}</c>) and shared across all tenants, so there
/// is no per-tenant routing — direct singleton access matches the bridge model's
/// pool-cache invariant.
/// </summary>
public interface ITenantStorageResolver
{
    /// <summary>
    /// Returns the registry-tier <see cref="IBlobStore"/> for <paramref name="tenantId"/>.
    /// Throws <see cref="TenantNotReadyException"/> when <c>orgs.status</c> is anything
    /// other than <c>active</c>, or when a <c>tenant_provisioning_jobs</c> row exists
    /// for <c>kind='registry_bucket_create'</c> with a state other than <c>ready</c>.
    /// Absent provisioning rows count as ready (community has no async provisioning).
    /// </summary>
    Task<IBlobStore> GetRegistryAsync(string tenantId, CancellationToken ct = default);

    /// <summary>
    /// Cache-tier blob store. Shared across all tenants by design — proxy artefacts are
    /// content-addressed and dedup-friendly. No tenant gate applies.
    /// </summary>
    IBlobStore Cache { get; }
}
