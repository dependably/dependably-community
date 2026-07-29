using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a real <see cref="BlockGateService"/> wired over an in-memory metadata store,
/// so controller-construction test helpers do not each re-assemble its dependency graph.
/// </summary>
public static class TestBlockGate
{
    /// <param name="anchors">
    /// Trust-anchor store backing the provenance arm's unbacked-enforcement check. Defaults to an
    /// empty stub, which only matters for a scenario that sets a verify policy to 'block' — that
    /// combination is exactly the fail-closed case, so a test asserting a serve under 'block' must
    /// pass a store seeded with an anchor for the ecosystem under test.
    /// </param>
    public static BlockGateService Create(
        IMetadataStore db, TimeProvider clock, IPerOrgTrustAnchorStore? anchors = null) =>
        new(
            new VulnerabilityRepository(db, clock),
            new AuditRepository(db),
            new QuarantineRepository(db, clock),
            new AlertService(new AlertRepository(db, clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(db, new MemoryCache(new MemoryCacheOptions()), clock),
            new LicenseRepository(db, clock, new LicenseNormalizer(db, NullLogger<LicenseNormalizer>.Instance)),
            anchors ?? new StubPerOrgTrustAnchorStore(),
            NullLogger<BlockGateService>.Instance,
            clock);
}
