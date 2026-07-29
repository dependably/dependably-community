using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a real <see cref="VulnerabilityScanService"/> wired over an in-memory metadata
/// store with an OSV source that returns no advisories, so controller-construction test helpers do
/// not each re-assemble its dependency graph. The scan still stamps <c>vuln_checked_at</c>, which is
/// what the block gate's vulnerability arms key off — an unscanned artefact fails those arms open.
/// </summary>
public static class TestScanner
{
    public static VulnerabilityScanService NoFindings(IMetadataStore db, TimeProvider clock)
    {
        // Route through TestOsvSource so the reachability-reporting TryQuery* pair is configured
        // too. Configuring only QueryAsync/QueryBatchAsync leaves the default-interface Try*
        // variants answering a null OsvQueryResult, which VulnerabilityScanService reads as
        // "source not reached" and refuses to stamp vuln_checked_at — leaving the block gate's
        // vulnerability arms with no facts to read.
        var osv = TestOsvSource.Create();

        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsEnabled.Returns(false);
        airGap.DisabledJobs.Returns(new HashSet<string>());
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);

        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            db,
            osv,
            new VulnerabilityRepository(db, clock),
            new AuditRepository(db),
            new ConfigurationBuilder().Build(),
            airGap,
            NullLogger<VulnerabilityScanService>.Instance,
            clock,
            new OrgRepository(db),
            Substitute.For<IPackageEventSink>(),
            new InProcessDistributedLock(clock),
            TestAlerts.NoOp(db, clock)));
    }
}
