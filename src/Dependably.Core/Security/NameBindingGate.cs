using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Name-level publish authorization: binds each <c>(org, ecosystem, purl_name)</c> to the
/// principal that first hosted-publishes it, and refuses later publishes by a different principal
/// unless it is the owner or holds an explicit grant. This is the control that answers "which
/// names may this credential write to" — the question a private registry exists to answer — so a
/// token scoped only to <c>publish:npm</c> can no longer seize any npm name in the org.
///
/// The principal is always the authenticated actor resolved from the token
/// (<see cref="NamePrincipal"/>), never a request-body/route field, so it cannot be spoofed.
///
/// Enforcement is opt-in via <c>PUBLISH_NAME_BINDING=on</c> (default off), because turning it on
/// binds every name to its first post-upgrade publisher and would otherwise break orgs that
/// legitimately publish one name from several principals (rotated CI tokens, shared packages) —
/// operators enable it once they have established grants. Ownership is nonetheless *recorded*
/// (trust-on-first-use) on every hosted publish regardless of the flag, so (a) the resurrection
/// tombstone that <see cref="ClaimResolver"/> reads is always populated, and (b) enabling
/// enforcement later has authoritative first-publisher data to enforce against.
/// </summary>
public sealed class NameBindingGate
{
    private readonly NameBindingRepository _bindings;
    private readonly ILogger<NameBindingGate> _logger;

    public NameBindingGate(IConfiguration config, NameBindingRepository bindings, ILogger<NameBindingGate> logger)
    {
        IsEnforced = string.Equals(
            (config["PUBLISH_NAME_BINDING"] ?? "off").Trim(),
            "on",
            StringComparison.OrdinalIgnoreCase);
        _bindings = bindings;
        _logger = logger;
    }

    /// <summary>True when <c>PUBLISH_NAME_BINDING=on</c>; ownership is still recorded when false.</summary>
    public bool IsEnforced { get; }

    /// <summary>
    /// Read-only authorization check, run before any blob is written. Returns true when the
    /// publish is permitted: enforcement off, an anonymous/background caller (no principal to
    /// attribute), an unbound name (this caller becomes the first owner), the owning principal,
    /// or a principal holding a grant. Returns false only when enforcement is on and a *different*
    /// principal already owns the name without a grant.
    /// </summary>
    public async Task<bool> IsPublishAuthorizedAsync(
        string orgId, string ecosystem, string purlName, NamePrincipal? principal, CancellationToken ct = default)
    {
        if (!IsEnforced || principal is not { } who)
        {
            return true;
        }

        var binding = await _bindings.GetBindingAsync(orgId, ecosystem, purlName, ct);
        if (binding is null || binding.IsOwnedBy(who))
        {
            return true;
        }

        if (await _bindings.HasGrantAsync(orgId, ecosystem, purlName, who, ct))
        {
            return true;
        }

        _logger.LogWarning(
            "Name-binding denied publish: principal {PrincipalKind}:{PrincipalId} is not the owner of " +
            "{Ecosystem}/{PurlName} in org {OrgId} and holds no grant.",
            who.Kind, who.Id, ecosystem, purlName, orgId);
        return false;
    }

    /// <summary>
    /// Records first-publisher ownership after a successful hosted publish (trust-on-first-use,
    /// no-op when a binding already exists). Called regardless of <see cref="IsEnforced"/> so the
    /// resurrection tombstone stays populated. No-op for an anonymous/background caller.
    /// </summary>
    public async Task RecordOwnershipAsync(
        string orgId, string ecosystem, string purlName, NamePrincipal? principal, CancellationToken ct = default)
    {
        if (principal is not { } who)
        {
            return;
        }

        await _bindings.BindIfAbsentAsync(orgId, ecosystem, purlName, who, ct);
    }
}
