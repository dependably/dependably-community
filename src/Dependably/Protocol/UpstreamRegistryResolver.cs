using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Resolves the priority-ordered upstream base URLs configured for an (org, ecosystem). The
/// fetch paths walk the returned list top-to-bottom, falling through to the next entry on
/// miss/unreachable.
///
/// An empty result means the org has configured no upstream for that ecosystem, which the proxy
/// treats as "proxying disabled for this ecosystem" — the per-ecosystem off switch. The resolver
/// is deliberately DB-only (no <c>IConfiguration</c> fallback): a silent fallback to a hardcoded
/// default would defeat that contract. Back-compatibility for existing installs is preserved by
/// seeding the standard public registries as real rows (see FirstBootService / SchemaInitializer).
/// </summary>
public sealed class UpstreamRegistryResolver
{
    private readonly UpstreamRegistryRepository _repo;

    public UpstreamRegistryResolver(UpstreamRegistryRepository repo) => _repo = repo;

    /// <summary>
    /// The configured upstream base URLs for an ecosystem, highest priority first, with any
    /// trailing slash trimmed so callers can append ecosystem-specific paths uniformly.
    /// </summary>
    public async Task<IReadOnlyList<string>> ResolveAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        var urls = await _repo.ListUrlsForEcosystemAsync(orgId, ecosystem, ct);
        return urls.Count == 0 ? urls : urls.Select(u => u.TrimEnd('/')).ToList();
    }
}
