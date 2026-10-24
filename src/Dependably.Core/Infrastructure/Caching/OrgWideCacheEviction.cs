using Dependably.Protocol;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Expires everything this replica has cached from one org's reserved namespaces and proxy
/// settings: the reservation list, the settings record, every rendered-metadata entry bound to
/// the org's epoch, and the org's package-lookup outcomes.
///
/// <para>This is the expansion behind an org-wide <see cref="MetadataInvalidation"/>
/// (<see cref="MetadataInvalidation.ForOrg"/>). <see cref="MetadataInvalidationCoordinator"/>
/// calls it for the replica that made the change and again for every peer that receives the
/// broadcast, so the two cannot disagree about what an org-wide change expires.</para>
///
/// <para><b>Order matters.</b> The inputs (reservation list, settings) are cleared before the
/// derived answers (rendered epoch, lookup outcomes) are expired. A render or lookup that starts
/// after its epoch or generation moved therefore reads its inputs after they were cleared, and
/// reads them from the store. Reversing the order opens a window in which a request on the fresh
/// epoch re-renders from the still-cached pre-change list or settings and caches that document
/// for the full metadata TTL. A read of the reservation list or the settings record that began
/// before the clear cannot cache what it read either: its generation guard is cancelled by
/// <see cref="ReservedNamespaceListCache.Invalidate"/> or
/// <see cref="OrgRepository.InvalidateSettingsCache"/>, before the epoch moves.</para>
///
/// <para>Every step is idempotent, so applying this twice for one change (the local call, then a
/// redelivered or self-addressed broadcast) costs one extra cache miss and nothing else.</para>
/// </summary>
public sealed class OrgWideCacheEviction
{
    private readonly ReservedNamespaceListCache _reservations;
    private readonly OrgRepository? _orgs;
    private readonly OrgCacheEpochStore? _epoch;
    private readonly PackageLookupCache? _lookups;

    /// <param name="reservations">The org's cached reserved-namespace list.</param>
    /// <param name="orgs">Owner of the org-settings cache; <see langword="null"/> where no settings cache exists.</param>
    /// <param name="epoch">The org's rendered-metadata epoch; <see langword="null"/> where nothing renders.</param>
    /// <param name="lookups">The package-lookup outcome cache; <see langword="null"/> where lookups are not served.</param>
    public OrgWideCacheEviction(
        ReservedNamespaceListCache reservations,
        OrgRepository? orgs = null,
        OrgCacheEpochStore? epoch = null,
        PackageLookupCache? lookups = null)
    {
        _reservations = reservations;
        _orgs = orgs;
        _epoch = epoch;
        _lookups = lookups;
    }

    /// <summary>Expires this replica's cached state for <paramref name="orgId"/>, inputs first.</summary>
    public void Evict(string orgId)
    {
        // Inputs: what a render or lookup reads to decide.
        _reservations.Invalidate(orgId);
        _orgs?.InvalidateSettingsCache(orgId);

        // Derived answers: expired only once their inputs re-read from the store.
        _epoch?.Invalidate(orgId);
        _lookups?.InvalidateOrg(orgId);
    }
}
