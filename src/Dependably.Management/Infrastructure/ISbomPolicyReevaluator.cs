namespace Dependably.Infrastructure;

/// <summary>
/// Re-runs the SBOM policy evaluation for one project version.
///
/// <para>The seam exists because a manual VEX triage changes a policy input: suppressing an
/// advisory can retire the finding it produced, and un-suppressing one can create a finding that
/// was not there a moment ago. The materialized <c>sbom_policy_findings</c> rows and the version's
/// <c>policy_status</c> rollup would otherwise keep describing the state before the operator's
/// decision — and an alert would keep firing on a finding the operator has already answered.</para>
///
/// <para>The read surface owns the trigger, not the evaluation: the evaluator itself lives with the
/// policy arms. <see cref="NoOpSbomPolicyReevaluator"/> is registered as the fail-safe default so
/// the triage write never depends on the evaluator being present, and a deployment that has one
/// registers it over the top.</para>
/// </summary>
public interface ISbomPolicyReevaluator
{
    Task ReevaluateAsync(string orgId, string projectVersionId, CancellationToken ct = default);
}

/// <summary>
/// Default binding: does nothing. Chosen deliberately over throwing — a triage decision has already
/// been persisted by the time the trigger fires, and failing the request would tell the operator
/// their decision did not land when it did. The stale findings are corrected by the next scan pass.
/// </summary>
public sealed class NoOpSbomPolicyReevaluator : ISbomPolicyReevaluator
{
    public Task ReevaluateAsync(string orgId, string projectVersionId, CancellationToken ct = default)
        => Task.CompletedTask;
}
