using System.Security.Claims;
using System.Text.Json;
using ITfoxtec.Identity.Saml2;

namespace Dependably.Infrastructure.Saml;

/// <summary>
/// Resolves a Dependably tenant role from SAML assertion claims using a priority chain:
///
/// 1. The tenant-configured <see cref="TenantSamlConfig.RoleAttribute"/> override, if set.
/// 2. A built-in list of common role/group claim types (Azure AD, Okta, generic).
///
/// Values are mapped via <see cref="TenantSamlConfig.RoleMapping"/> (JSON dict); the
/// highest-precedence match wins (owner > admin > auditor > member). When no mapping is
/// configured or no value matches, returns <see cref="TenantSamlConfig.DefaultRole"/>.
///
/// <c>system_admin</c> is never a valid output — role targets are tenant roles only.
/// </summary>
public static class RoleAttributeResolver
{
    private static readonly string[] ValidTenantRoles = ["owner", "admin", "auditor", "member"];

    public static readonly IReadOnlyList<string> DefaultRoleClaimTypes = new[]
    {
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role",
        "Role",
        "groups",
        "Group",
    };

    /// <summary>
    /// Returns the highest-precedence mapped role, or <paramref name="cfg"/>.DefaultRole when
    /// no mapping matches.
    /// </summary>
    public static string Resolve(Saml2AuthnResponse response, TenantSamlConfig cfg)
        => Resolve(response.ClaimsIdentity.Claims, cfg);

    /// <summary>
    /// Claims-based overload: resolves the role directly from assertion claims, decoupled
    /// from the SAML2 response wrapper so the precedence/mapping logic is unit-testable.
    /// </summary>
    public static string Resolve(IEnumerable<Claim> claims, TenantSamlConfig cfg)
    {
        var mapping = ParseMapping(cfg.RoleMapping);
        if (mapping.Count == 0)
        {
            return SanitizeRole(cfg.DefaultRole);
        }

        var idpValues = GetRoleValues(claims, cfg.RoleAttribute);
        return BestMatch(idpValues, mapping) ?? SanitizeRole(cfg.DefaultRole);
    }

    /// <summary>Returns all IdP role/group claim values from the assertion.</summary>
    public static IReadOnlyList<string> GetRoleValues(IEnumerable<Claim> claims, string? configuredAttribute)
    {
        var claimList = claims.ToList();
        if (!string.IsNullOrWhiteSpace(configuredAttribute))
        {
            return claimList
                .Where(c => string.Equals(c.Type, configuredAttribute, StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .ToList();
        }
        // Built-in list: first claim type that has any value wins.
        foreach (string name in DefaultRoleClaimTypes)
        {
            var values = claimList
                .Where(c => string.Equals(c.Type, name, StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .ToList();
            if (values.Count > 0)
            {
                return values;
            }
        }
        return Array.Empty<string>();
    }

    private static string? BestMatch(IReadOnlyList<string> idpValues, Dictionary<string, string> mapping)
    {
        string? best = null;
        int bestPrecedence = int.MaxValue;
        foreach (string v in idpValues)
        {
            if (mapping.TryGetValue(v, out string? mapped))
            {
                int idx = Array.IndexOf(ValidTenantRoles, mapped);
                if (idx >= 0 && idx < bestPrecedence)
                {
                    bestPrecedence = idx;
                    best = mapped;
                }
            }
        }
        return best;
    }

    private static string SanitizeRole(string? role)
    {
        return role is not null && Array.IndexOf(ValidTenantRoles, role) >= 0 ? role : "member";
    }

    private static Dictionary<string, string> ParseMapping(string? json)
    {
        var safe = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json))
        {
            return safe;
        }

        try
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (raw is null)
            {
                return safe;
            }
            // Strip any attempt to assign system_admin.
            foreach (var (k, v) in raw)
            {
                string? role = v?.ToLowerInvariant();
                if (Array.IndexOf(ValidTenantRoles, role) >= 0)
                {
                    safe[k] = role!;
                }
            }
            return safe;
        }
        catch { return safe; }
    }
}
