using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;

namespace Dependably.Storage;

/// <summary>
/// Community pool-mode <see cref="ITenantStorageResolver"/>. Returns the singleton
/// registry and cache stores from <see cref="TieredBlobStorage"/> regardless of
/// <c>tenantId</c>, but still applies the lifecycle, usage-posture and provisioning-state
/// gates defensively — a hand-modified <c>orgs.status</c> row, or a management-plane import
/// into an org at its usage cap, can't slip through.
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

    public async Task<IBlobStore> GetRegistryAsync(string tenantId, bool forWrite = false, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // Gate 1: tenant lifecycle status. The CHECK constraint on orgs.status keeps this
        // bounded to active|suspended|archived|deleting|read_only. The query returns null when
        // the org row is missing — that's also a refusal. usage_posture rides the same row read
        // for Gate 1b below.
        var row = await conn.QuerySingleOrDefaultAsync<OrgGateRow>(
            "SELECT status AS Status, usage_posture AS UsagePosture FROM orgs WHERE id = @tenantId",
            new { tenantId }) ?? throw new TenantNotReadyException(tenantId, TenantNotReadyReason.NotFound, "tenant not found");
        string status = row.Status;
        if (status == "read_only")
        {
            // Narrower than the other non-active values: a read intent is admitted (the org's
            // existing registry-tier artefacts stay servable), a write intent is refused — same
            // defence-in-depth posture as TenantStatusEnforcementMiddleware's protocol-plane write
            // gate, independent of whichever surface called this resolver.
            if (forWrite)
            {
                throw new TenantNotReadyException(tenantId, TenantNotReadyReason.ReadOnlyWrite, "status='read_only'");
            }
        }
        else if (status != "active")
        {
            throw new TenantNotReadyException(tenantId, TenantNotReadyReason.StatusInactive, $"status='{status}'");
        }

        // Gate 1b: usage posture. The same refusal TenantStatusEnforcementMiddleware applies to a
        // protocol-plane write, applied here to a write intent on any surface — the
        // management-plane bulk import (ImportController) never crosses that middleware's
        // protocol-plane check but still writes hosted artefact bytes, which is exactly what an
        // org at its usage cap must not grow. A read intent is never gated by posture: downloads
        // keep working at the cap.
        if (forWrite && UsagePostures.RefusesUploads(row.UsagePosture))
        {
            throw new TenantNotReadyException(tenantId, TenantNotReadyReason.UsageCapReached,
                $"usage_posture='{row.UsagePosture}'");
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

    private sealed class OrgGateRow
    {
        public string Status { get; init; } = "";
        public string? UsagePosture { get; init; }
    }
}
