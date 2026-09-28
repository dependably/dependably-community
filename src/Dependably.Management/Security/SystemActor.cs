using System.Security.Claims;
using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Resolves the audit-attribution shape for a system-realm principal — a system_admin JWT
/// session or a <c>dpsys_…</c> system token — so the tenant-lifecycle and usage-limit actions on
/// <c>SystemController</c> share one place that decides how to attribute each. A JWT session
/// carries its admin id as <c>Id</c> and everything else null; a token principal carries the
/// token's own id as <c>Id</c> (never the owner's — <see cref="SystemTokenAuthenticationHandler"/>
/// never puts the owner in <c>sub</c>), <see cref="ActorKinds.Service"/> as <c>Kind</c>, the
/// token's display name as <c>Label</c>, and the minting admin's id as <c>OwnerId</c> for the
/// audit detail's <c>via_token_owner</c> field.
/// </summary>
public readonly record struct SystemActor(string? Id, string? Kind, string? Label, string? OwnerId)
{
    public static SystemActor From(ClaimsPrincipal user)
    {
        bool isToken = user.Identities.Any(i => i.AuthenticationType == SystemTokenDefaults.Scheme);
        if (!isToken)
        {
            string? adminId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? user.FindFirst("sub")?.Value;
            return new SystemActor(adminId, null, null, null);
        }

        string? tokenId = user.FindFirst("sub")?.Value;
        string? name = user.FindFirst("stok_name")?.Value;
        string? owner = user.FindFirst("stok_owner")?.Value;
        return new SystemActor(tokenId, ActorKinds.Service, name, owner);
    }
}
