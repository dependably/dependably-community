namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Marks a protocol-plane POST/PUT/PATCH that <see cref="TenantStatusEnforcementMiddleware"/>
/// admits under a usage cap because the action can only lower usage: a prune or unpublish step
/// that a client sends with a non-DELETE method. Never for an action that can ingest an artefact.
/// The admission is read from endpoint metadata, so it applies to exactly the marked action; it
/// has no effect on the <c>read_only</c> status gate, which keeps refusing the request. The set of
/// marked actions is pinned by <c>UsageCapAdmittedWriteComplianceTests</c>.
/// </summary>
/// <remarks>
/// Method-only: a class-level target would let one attribute admit every write on a controller.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
public sealed class UsageCapAdmittedWriteAttribute : Attribute
{
    public UsageCapAdmittedWriteAttribute(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException("A usage-cap admission must state why the action cannot raise usage.", nameof(reason));
        }

        Reason = reason;
    }

    /// <summary>Why the action can only lower usage, reviewable at the call site.</summary>
    public string Reason { get; }
}
