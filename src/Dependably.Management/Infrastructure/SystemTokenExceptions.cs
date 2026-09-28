namespace Dependably.Infrastructure;

/// <summary>
/// Thrown by <see cref="SystemTokenRepository.CreateAsync"/> when the instance already holds its
/// maximum number of active system tokens. Deliberately a distinct type from
/// <see cref="TokenCapExceededException"/> — that type's message and <c>OrgId</c> property are
/// tenant-shaped, and reusing it here would misword the instance-level cap as a tenant one.
/// Carries the observed count and the ceiling so the caller can render the same message a
/// pre-check would have, without repeating the count outside the transaction that enforced it.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class SystemTokenCapExceededException : Exception
{
    public SystemTokenCapExceededException(int activeCount, int cap)
        : base($"Instance has {activeCount} active system tokens, at or above the cap of {cap}.")
    {
        ActiveCount = activeCount;
        Cap = cap;
    }

    public int ActiveCount { get; }

    /// <summary>The enforced ceiling — <see cref="SystemTokenRepository"/>'s fixed instance-wide cap.</summary>
    public int Cap { get; }
}

/// <summary>
/// Thrown by <see cref="SystemTokenRepository.CreateAsync"/> when the minting admin's session is
/// no longer current at the moment the insert executes — the account was disabled/locked, or
/// <c>token_version</c> moved on (a password change or an admin-initiated reset) after the caller's
/// JWT was validated but before the transactional insert ran. The JwtBearer token-version check
/// is cache-backed (<c>SystemAdminTokenVersionStore</c>, up to 60s TTL on a single-replica
/// deployment), so a session invalidated by a concurrent write can still pass that outer gate for
/// the remainder of its cache window; this is the inner, transactional check that closes the gap
/// for the one action — minting a durable credential — where it matters.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class SystemTokenOwnerSessionStaleException : Exception
{
    public SystemTokenOwnerSessionStaleException(string ownerId)
        : base($"System admin '{ownerId}' is no longer active under the presented session's token version.")
    {
        OwnerId = ownerId;
    }

    public string OwnerId { get; }
}
