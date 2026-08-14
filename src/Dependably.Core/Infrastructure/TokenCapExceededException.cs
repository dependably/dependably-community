namespace Dependably.Infrastructure;

/// <summary>
/// Thrown by <see cref="TokenRepository"/> when a tenant already holds its maximum number of
/// active tokens. Carries the observed count and the ceiling so the caller can render the same
/// message a pre-check would have, without repeating the count outside the transaction that
/// enforced it.
/// </summary>
public sealed class TokenCapExceededException : Exception
{
    public TokenCapExceededException(string orgId, int activeCount, int cap)
        : base($"Tenant has {activeCount} active tokens, at or above the cap of {cap}.")
    {
        OrgId = orgId;
        ActiveCount = activeCount;
        Cap = cap;
    }

    public string OrgId { get; }

    public int ActiveCount { get; }

    /// <summary>The enforced ceiling — <c>instance_settings.max_active_tokens_per_tenant</c>.</summary>
    public int Cap { get; }
}
