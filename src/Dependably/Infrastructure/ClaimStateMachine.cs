namespace Dependably.Infrastructure;

/// <summary>
/// Encodes the legal claim transitions. Pure logic, no DB access — paired with
/// <see cref="ClaimRepository"/> at the call site.
///
/// Transition table:
/// <code>
/// from         to            allowed   side effect
/// ───────────────────────────────────────────────────────────
/// (none)       local_only    yes       purge proxy artifacts (count returned to caller)
/// (none)       mixed         yes       (warning surfaced in UI; supply-chain implication)
/// local_only   mixed         yes       enables proxy fallback
/// mixed        local_only    yes       purge proxy artifacts
/// local_only   (release)     yes IFF zero local versions
/// mixed        (release)     yes IFF zero local versions; cached proxy retained
/// </code>
///
/// Anything else → <see cref="ClaimTransitionResult.Reject"/> with a structured reason.
/// </summary>
public static class ClaimStateMachine
{
    public const string Unclaimed = "unclaimed";
    public const string LocalOnly = "local_only";
    public const string Mixed = "mixed";

    /// <summary>
    /// Validate creation of a new claim. Current state is implicit-unclaimed; <paramref name="targetState"/>
    /// must be <c>local_only</c> or <c>mixed</c>.
    /// </summary>
    public static ClaimTransitionResult ValidateCreate(string targetState)
    {
        return targetState is not (LocalOnly or Mixed)
            ? ClaimTransitionResult.Reject(
                $"Cannot create claim with state '{targetState}'. Use 'local_only' or 'mixed'.")
            : ClaimTransitionResult.Allow(purgesProxy: targetState == LocalOnly);
    }

    /// <summary>
    /// Validate moving an existing claim from <paramref name="from"/> to <paramref name="to"/>.
    /// </summary>
    public static ClaimTransitionResult ValidateChange(string from, string to)
    {
        return from == to
            ? ClaimTransitionResult.Reject("Claim is already in that state.")
            : (from, to) switch
            {
                (LocalOnly, Mixed) => ClaimTransitionResult.Allow(purgesProxy: false),
                (Mixed, LocalOnly) => ClaimTransitionResult.Allow(purgesProxy: true),
                _ => ClaimTransitionResult.Reject(
                    $"Transition '{from}' → '{to}' is not supported. Allowed: local_only ↔ mixed; release via DELETE.")
            };
    }

    /// <summary>
    /// Validate releasing a claim back to unclaimed. Requires zero local versions for the name.
    /// </summary>
    public static ClaimTransitionResult ValidateRelease(string from, int localVersionCount)
    {
        return localVersionCount > 0
            ? ClaimTransitionResult.Reject(
                $"Cannot release: {localVersionCount} local version(s) still exist for this name. " +
                "Delete them first.")
            : ClaimTransitionResult.Allow(purgesProxy: false);
    }
}

public readonly record struct ClaimTransitionResult(bool Allowed, string? RejectionReason, bool PurgesProxy)
{
    public static ClaimTransitionResult Allow(bool purgesProxy) =>
        new(true, null, purgesProxy);

    public static ClaimTransitionResult Reject(string reason) =>
        new(false, reason, false);
}
