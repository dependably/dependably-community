using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

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
    /// <param name="eventSink">
    /// Webhook dispatch seam for the <c>package.blocked</c> event. Defaults to a discarding
    /// substitute; a test asserting on dispatch passes its own so it can inspect received calls.
    /// </param>
    /// <param name="webhookThrottle">
    /// Burst throttle in front of that dispatch. Defaults to a real throttle sharing the caller's
    /// clock with a zero window, so every refusal in a test that does not itself exercise
    /// coalescing dispatches — tests asserting the throttle's own behaviour pass a non-zero window.
    /// </param>
    public static BlockGateService Create(
        IMetadataStore db,
        TimeProvider clock,
        IPerOrgTrustAnchorStore? anchors = null,
        IPackageEventSink? eventSink = null,
        BlockRefusalWebhookThrottle? webhookThrottle = null) =>
        new(
            new VulnerabilityRepository(db, clock),
            new AuditRepository(db),
            new QuarantineRepository(db, clock),
            new AlertService(new AlertRepository(db, clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(db, new MemoryCache(new MemoryCacheOptions()), clock),
            new LicenseRepository(db, clock, new LicenseNormalizer(db, NullLogger<LicenseNormalizer>.Instance)),
            anchors ?? new StubPerOrgTrustAnchorStore(),
            NullLogger<BlockGateService>.Instance,
            clock,
            new OrgRepository(db),
            eventSink ?? Substitute.For<IPackageEventSink>(),
            webhookThrottle ?? new BlockRefusalWebhookThrottle(clock, TimeSpan.Zero));
}
