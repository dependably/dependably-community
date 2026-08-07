using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Pins the invariant that keeps proxied Portable PDBs out of the per-tenant package catalogue.
/// <see cref="NuGetSymbolProxyFetcher.SymbolEcosystem"/> and
/// <see cref="CatalogueHiddenEcosystems"/> are two independent lists that must agree — a drift
/// would make a proxied PDB start appearing as a package named <c>mylib.pdb</c> with no error
/// anywhere, since neither list references the other at compile time.
/// </summary>
public sealed class NuGetSymbolProxyFetcherTests
{
    [Fact]
    public void SymbolEcosystem_IsCoveredByCatalogueHiddenEcosystems()
    {
        Assert.True(
            CatalogueHiddenEcosystems.Covers(NuGetSymbolProxyFetcher.SymbolEcosystem),
            $"'{NuGetSymbolProxyFetcher.SymbolEcosystem}' must be listed in " +
            $"{nameof(CatalogueHiddenEcosystems)}; without it, proxied PDBs are catalogued as packages.");
    }
}
