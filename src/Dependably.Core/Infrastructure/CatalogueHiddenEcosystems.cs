namespace Dependably.Infrastructure;

/// <summary>
/// Ecosystems whose artefacts live on the global cache plane but are deliberately absent from the
/// per-tenant package catalogue — no <c>packages</c> row, so they never appear in package lists,
/// search, or the ecosystem filter.
///
/// <para>
/// The member is <c>nuget-symbols</c>: a proxied Portable PDB fetched over SSQP. A debug-id carries
/// no package identity, so its cache coordinate is (pdb filename, debug-id) — content-addressed the
/// way OCI is by digest. Cataloguing that would list a "package" named <c>mylib.pdb</c> at a
/// 40-hex "version", under an ecosystem the frontend has no label for.
/// </para>
///
/// <para>
/// Hidden from the catalogue is NOT hidden from the platform: these artefacts still land on
/// <c>cache_artifact</c> + <c>tenant_artifact_access</c>, so they remain block-gated, scanned,
/// counted against tenant storage, and reclaimable by cache eviction. Only the browse surfaces
/// skip them.
/// </para>
/// </summary>
public static class CatalogueHiddenEcosystems
{
    public static readonly IReadOnlySet<string> Hidden =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "nuget-symbols",
        };

    public static bool Covers(string ecosystem) => Hidden.Contains(ecosystem);
}
