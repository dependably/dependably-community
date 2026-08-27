namespace Dependably.Infrastructure;

/// <summary>
/// Binds the triage trigger to the real policy evaluator, so a manual VEX decision restamps
/// <c>sbom_policy_findings</c> and the version's <c>policy_status</c> immediately rather than
/// waiting for the next scan pass.
/// </summary>
public sealed class SbomPolicyReevaluator : ISbomPolicyReevaluator
{
    private readonly Dependably.Protocol.SbomPolicyEvaluationService _policy;

    public SbomPolicyReevaluator(Dependably.Protocol.SbomPolicyEvaluationService policy)
        => _policy = policy;

    public Task ReevaluateAsync(string orgId, string projectVersionId, CancellationToken ct = default)
        => _policy.EvaluateAndPersistAsync(orgId, projectVersionId, ct);
}
