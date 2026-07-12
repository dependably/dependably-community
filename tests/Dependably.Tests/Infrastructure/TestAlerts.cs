using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a real <see cref="AlertService"/> wired over an in-memory metadata store with
/// a no-op notifier, so BlockGateService/VulnerabilityScanService construction test helpers do
/// not each re-assemble its dependency graph.
/// </summary>
public static class TestAlerts
{
    public static AlertService NoOp(IMetadataStore db, TimeProvider clock) =>
        new(new AlertRepository(db, clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance);
}
