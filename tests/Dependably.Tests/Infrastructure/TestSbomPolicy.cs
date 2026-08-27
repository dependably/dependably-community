using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a real <see cref="SbomPolicyEvaluationService"/> over an in-memory metadata
/// store, so the many <see cref="VulnerabilityScanService"/> construction helpers do not each
/// re-assemble its dependency graph. Mirrors <see cref="TestAlerts"/>.
/// </summary>
public static class TestSbomPolicy
{
    public static SbomPolicyEvaluationService Service(IMetadataStore db, TimeProvider clock) =>
        new(
            new SbomPolicyRepository(db, clock),
            new OrgRepository(db),
            new LicenseRepository(db, clock, TestNormalizers.License(db)),
            TestAlerts.NoOp(db, clock),
            new AuditRepository(db, activityWriter: null, clock),
            NullLogger<SbomPolicyEvaluationService>.Instance);
}
