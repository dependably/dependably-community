using System.Security.Claims;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;

namespace Dependably.Infrastructure.Saml;

/// <summary>
/// Picks an email address out of a SAML AuthnResponse using a fixed priority chain:
///
/// 1. The tenant-configured <see cref="TenantSamlConfig.EmailAttribute"/> override, if set
///    (case-insensitive claim type match).
/// 2. A small whitelist of common email claim types issued by Okta / AzureAD / ADFS, in
///    priority order — see <see cref="DefaultEmailClaimTypes"/>.
/// 3. The NameID value when it has email-format NameIdFormat, or when it contains '@'.
///
/// Adding a new IdP that uses a non-standard claim is a one-line addition to
/// <see cref="DefaultEmailClaimTypes"/> plus a unit test.
/// </summary>
public static class EmailAttributeResolver
{
    public static readonly IReadOnlyList<string> DefaultEmailClaimTypes = new[]
    {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "urn:oid:0.9.2342.19200300.100.1.3",
        "email",
        "mail",
        "EmailAddress",
    };

    public static string? Resolve(Saml2AuthnResponse response, TenantSamlConfig cfg)
    {
        var claims = response.ClaimsIdentity.Claims;

        string? configured = FromAttributeOverride(claims, cfg.EmailAttribute);
        if (configured is not null)
        {
            return configured;
        }

        string? standard = FromCommonClaimTypes(claims);
        if (standard is not null)
        {
            return standard;
        }

        // Fall back to NameID when its format is the email format, or the value
        // looks like an email. NameId type comes from ITfoxtec.Saml2; we read its
        // Format/Value via duck typing rather than naming the concrete type so we
        // don't take a direct dependency on a versioned internal class.
        string? format = response.NameId?.Format?.OriginalString;
        string? value = response.NameId?.Value;
        return string.IsNullOrWhiteSpace(value)
            ? null
            : format is null
            || format.Equals(NameIdentifierFormats.Email.OriginalString, StringComparison.OrdinalIgnoreCase)
            || value.Contains('@')
            ? value
            : null;
    }

    private static string? FromAttributeOverride(IEnumerable<Claim> claims, string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured))
        {
            return null;
        }

        var match = claims.FirstOrDefault(c =>
            string.Equals(c.Type, configured, StringComparison.OrdinalIgnoreCase));
        return string.IsNullOrWhiteSpace(match?.Value) ? null : match.Value;
    }

    private static string? FromCommonClaimTypes(IEnumerable<Claim> claims)
    {
        var asList = claims.ToList();
        foreach (string name in DefaultEmailClaimTypes)
        {
            var match = asList.FirstOrDefault(c =>
                string.Equals(c.Type, name, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(match?.Value))
            {
                return match.Value;
            }
        }
        return null;
    }
}
