namespace Dependably.Infrastructure;

/// <summary>
/// Returns the effective claim state for <c>(org, ecosystem, name)</c>. Honors air-gap mode:
/// when <see cref="IAirGapMode.IsEnabled"/> is true, every name resolves to
/// <see cref="ClaimStateMachine.LocalOnly"/> implicitly, even if no <c>claim</c> row exists.
/// Operators can still create explicit claim rows in air-gap mode for auditing — those rows
/// are honored if present.
///
/// In connected deployments, a missing claim row resolves by hosted content
/// (dependency-confusion guard): a name the org has at least one hosted
/// (origin='uploaded') version for is implicitly <see cref="ClaimStateMachine.LocalOnly"/>
/// — upstream must not be able to shadow it — while a name with no hosted versions stays
/// <see cref="ClaimStateMachine.Unclaimed"/>. An explicit <c>mixed</c> claim remains the
/// deliberate operator opt-in to upstream merging on a hosted name.
///
/// Resolutions are computed per call (no caching here), so the implicit state flips as soon
/// as the first hosted version lands.
/// </summary>
public sealed class ClaimResolver
{
    private readonly ClaimRepository _claims;
    private readonly IAirGapMode _airGap;
    private readonly NameBindingRepository? _nameBindings;

    // nameBindings is optional so the many test constructions that predate the name-binding
    // model keep compiling; production DI always injects the registered repository, which
    // enables the resurrection tombstone below.
    public ClaimResolver(ClaimRepository claims, IAirGapMode airGap, NameBindingRepository? nameBindings = null)
    {
        _claims = claims;
        _airGap = airGap;
        _nameBindings = nameBindings;
    }

    /// <summary>
    /// Returns the effective state plus an optional <c>Claim</c> row if one exists.
    /// </summary>
    public async Task<EffectiveClaim> ResolveAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        var explicitClaim = await _claims.GetAsync(orgId, ecosystem, name, ct);
        if (explicitClaim is not null)
        {
            return new EffectiveClaim(explicitClaim.State, explicitClaim, IsImplicit: false);
        }

        if (_airGap.IsEnabled)
        {
            return new EffectiveClaim(ClaimStateMachine.LocalOnly, null, IsImplicit: true);
        }

        // Hosted-name shadowing guard: a name with hosted versions but no claim row is
        // implicitly local_only so the proxy never merges or fetches upstream for it.
        //
        // Resurrection tombstone: a name-binding row records that this org has hosted-published
        // the name at least once. It outlives deletion of the last hosted version (it is keyed to
        // the org, not the packages row), so a routine bad-release rollback that deletes every
        // version no longer silently reverts the name to Unclaimed — where the proxy would fetch a
        // squatter's package from the public registry (dependency-confusion resurrection). An
        // explicit claim still overrides this, the deliberate operator opt-in back to upstream.
        bool hostedOnceOrOwned =
            await _claims.HasUploadedVersionsAsync(orgId, ecosystem, name, ct)
            || (_nameBindings is not null
                && await _nameBindings.HasBindingAsync(orgId, ecosystem, name, ct));
        string defaultState = hostedOnceOrOwned
            ? ClaimStateMachine.LocalOnly
            : ClaimStateMachine.Unclaimed;
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
