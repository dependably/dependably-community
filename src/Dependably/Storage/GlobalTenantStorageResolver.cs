using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Storage;

/// <summary>
/// Community pool-mode <see cref="ITenantStorageResolver"/>. Returns the singleton
/// registry and cache stores from <see cref="TieredBlobStorage"/> regardless of
/// <c>tenantId</c>, but still applies the lifecycle and provisioning-state gates
/// defensively — a hand-modified <c>orgs.status</c> row or a future enterprise import
/// path can't slip through.
///
/// Enterprise's resolver lives out of tree and consults <c>tenant_storage</c> to
/// return per-tenant <see cref="S3BlobStore"/> instances. It applies the same gates,
/// reusing this implementation's queries.
/// </summary>
public sealed class GlobalTenantStorageResolver : ITenantStorageResolver
{
    private readonly IMetadataStore _db;
    private readonly TieredBlobStorage _tiered;

    public GlobalTenantStorageResolver(IMetadataStore db, TieredBlobStorage tiered)
    {
        _db = db;
        _tiered = tiered;
    }

    public IBlobStore Cache => _tiered.Cache;

    public async Task<IBlobStore> GetRegistryAsync(string tenantId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Gate 1: tenant lifecycle status. The CHECK constraint on orgs.status keeps this
        // bounded to active|suspended|archived|deleting; anything but 'active' refuses.
        // The query returns null when the org row is missing — that's also a refusal.
        string status = await conn.QuerySingleOrDefaultAsync<string?>(
            "SELECT status FROM orgs WHERE id = @tenantId",
            new { tenantId }) ?? throw new TenantNotReadyException(tenantId, TenantNotReadyReason.NotFound, "tenant not found");
        if (status != "active")
        {
            throw new TenantNotReadyException(tenantId, TenantNotReadyReason.StatusInactive, $"status='{status}'");
        }

        // Gate 2: async provisioning state for the registry bucket. Absent row counts as
        // ready (community LocalBlobStore is synchronous; enterprise inserts a 'creating'
        // row at tenant create and the worker transitions it). A 'failed' row stays put
        // until the worker retries via UPDATE — no row deletion, no INSERT-on-retry.
        string? provisioningState = await conn.QuerySingleOrDefaultAsync<string?>(
            "SELECT state FROM tenant_provisioning_jobs " +
            "WHERE org_id = @tenantId AND kind = 'registry_bucket_create'",
            new { tenantId });
        if (provisioningState == "creating")
        {
            throw new TenantNotReadyException(tenantId, TenantNotReadyReason.ProvisioningPending,
                "provisioning state='creating'");
        }

        if (provisioningState == "failed")
        {
            throw new TenantNotReadyException(tenantId, TenantNotReadyReason.ProvisioningFailed,
                "provisioning state='failed'");
        }

        // Community pool: all tenants share the singleton registry. Enterprise overrides
        // this to consult tenant_storage and return the tenant's silo bucket store.
        return _tiered.Registry;
    }
}
