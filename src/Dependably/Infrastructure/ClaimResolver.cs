namespace Dependably.Infrastructure;

/// <summary>
/// Returns the effective claim state for <c>(org, ecosystem, name)</c>. Honors air-gap mode:
/// when <see cref="IAirGapMode.IsEnabled"/> is true, every name resolves to
/// <see cref="ClaimStateMachine.LocalOnly"/> implicitly, even if no <c>claim</c> row exists.
/// Operators can still create explicit claim rows in air-gap mode for auditing — those rows
/// are honored if present.
///
/// In connected deployments, missing claim row → <see cref="ClaimStateMachine.Unclaimed"/>.
/// </summary>
public sealed class ClaimResolver
{
    private readonly ClaimRepository _claims;
    private readonly IAirGapMode _airGap;

    public ClaimResolver(ClaimRepository claims, IAirGapMode airGap)
    {
        _claims = claims;
        _airGap = airGap;
    }

    /// <summary>
    /// Returns the effective state plus an optional <c>Claim</c> row if one exists.
    /// </summary>
    public async Task<EffectiveClaim> ResolveAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        var explicitClaim = await _claims.GetAsync(orgId, ecosystem, name, ct);
        if (explicitClaim is not null)
            return new EffectiveClaim(explicitClaim.State, explicitClaim, IsImplicit: false);

        var defaultState = _airGap.IsEnabled ? ClaimStateMachine.LocalOnly : ClaimStateMachine.Unclaimed;
        return new EffectiveClaim(defaultState, null, IsImplicit: true);
    }

    /// <summary>
    /// Convenience: <see langword="true"/> if a publish/import to the given name is allowed
    /// under the current claim state. Unclaimed names reject; local_only and mixed accept.
    /// </summary>
    public async Task<bool> CanPublishAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        var eff = await ResolveAsync(orgId, ecosystem, name, ct);
        return eff.State is ClaimStateMachine.LocalOnly or ClaimStateMachine.Mixed;
    }

    /// <summary>
    /// <see langword="true"/> if proxy fetch / pass-through is permitted for the given name.
    /// <c>local_only</c> rejects (proxy is disabled, including the implicit local_only that
    /// air-gap mode applies to every name); <c>unclaimed</c> and <c>mixed</c> accept.
    /// </summary>
    public async Task<bool> IsProxyFetchAllowedAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        var eff = await ResolveAsync(orgId, ecosystem, name, ct);
        return eff.State != ClaimStateMachine.LocalOnly;
    }
}

public sealed record EffectiveClaim(string State, NameClaim? Row, bool IsImplicit);
