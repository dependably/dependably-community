using System.Security.Claims;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Saml;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="EmailAttributeResolver"/>. The resolver reads only
/// <c>ClaimsIdentity</c> and <c>NameId</c> off the SDK <see cref="Saml2AuthnResponse"/> —
/// both are settable, so we build minimal responses directly without parsing real SAML XML.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailAttributeResolverTests
{
    private static Saml2AuthnResponse BuildResponse(
        IEnumerable<Claim>? claims = null,
        string? nameIdValue = null,
        string? nameIdFormat = null)
    {
        var response = new Saml2AuthnResponse(new Saml2Configuration())
        {
            ClaimsIdentity = new ClaimsIdentity(claims ?? Array.Empty<Claim>()),
        };
        if (nameIdValue is not null)
        {
            response.NameId = nameIdFormat is null
                ? new Saml2NameIdentifier(nameIdValue)
                : new Saml2NameIdentifier(nameIdValue, new Uri(nameIdFormat));
        }
        return response;
    }

    private static TenantSamlConfig Cfg(string? emailAttribute = null) =>
        new() { OrgId = "org-1", EmailAttribute = emailAttribute };

    // ── 1. Config override path ───────────────────────────────────────────────

    [Fact]
    public void Override_ExactCaseMatch_Wins()
    {
        var response = BuildResponse(new[]
        {
            new Claim("custom_mail", "user@example.com"),
            new Claim("email", "ignored@example.com"),
        });

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("custom_mail")));
    }

    [Fact]
    public void Override_CaseInsensitiveClaimTypeMatch()
    {
        var response = BuildResponse(new[]
        {
            new Claim("Custom_Mail", "user@example.com"),
        });

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("CUSTOM_MAIL")));
    }

    [Fact]
    public void Override_TakesPrecedenceOverDefaultsAndNameId()
    {
        var response = BuildResponse(
            claims: new[]
            {
                new Claim("custom_mail", "override@example.com"),
                new Claim("email", "default@example.com"),
            },
            nameIdValue: "nameid@example.com",
            nameIdFormat: NameIdentifierFormats.Email.OriginalString);

        Assert.Equal("override@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("custom_mail")));
    }

    [Fact]
    public void Override_MissingAttribute_FallsThroughToDefaults()
    {
        var response = BuildResponse(new[]
        {
            new Claim("email", "default@example.com"),
        });

        Assert.Equal("default@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("missing_attr")));
    }

    [Fact]
    public void Override_WhitespaceValue_FallsThroughToDefaults()
    {
        var response = BuildResponse(new[]
        {
            new Claim("custom_mail", "   "),       // whitespace-only override hit
            new Claim("email", "default@example.com"),
        });

        Assert.Equal("default@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("custom_mail")));
    }

    [Fact]
    public void Override_EmptyConfigured_FallsThroughToDefaults()
    {
        var response = BuildResponse(new[]
        {
            new Claim("email", "default@example.com"),
        });

        // EmailAttribute null/empty/whitespace all skip the override branch.
        Assert.Equal("default@example.com", EmailAttributeResolver.Resolve(response, Cfg(null)));
        Assert.Equal("default@example.com", EmailAttributeResolver.Resolve(response, Cfg("")));
        Assert.Equal("default@example.com", EmailAttributeResolver.Resolve(response, Cfg("   ")));
    }

    [Fact]
    public void Override_FirstClaimWinsWhenMultiple()
    {
        // ClaimsIdentity preserves insertion order; FirstOrDefault picks the first.
        var response = BuildResponse(new[]
        {
            new Claim("custom_mail", "first@example.com"),
            new Claim("custom_mail", "second@example.com"),
        });

        Assert.Equal("first@example.com",
            EmailAttributeResolver.Resolve(response, Cfg("custom_mail")));
    }

    // ── 2. Default claim-type path ────────────────────────────────────────────

    [Fact]
    public void Defaults_FirstWhitelistEntryWins()
    {
        // Both the XML-schema URI and the short 'email' name are present; the URI
        // appears first in DefaultEmailClaimTypes, so it wins.
        var response = BuildResponse(new[]
        {
            new Claim("email", "shortname@example.com"),
            new Claim(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "wsclaim@example.com"),
        });

        Assert.Equal("wsclaim@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void Defaults_UrnOidClaim_Resolves()
    {
        var response = BuildResponse(new[]
        {
            new Claim("urn:oid:0.9.2342.19200300.100.1.3", "ldap@example.com"),
        });

        Assert.Equal("ldap@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void Defaults_MailClaim_Resolves()
    {
        var response = BuildResponse(new[]
        {
            new Claim("mail", "azuread@example.com"),
        });

        Assert.Equal("azuread@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void Defaults_EmailAddressClaim_Resolves()
    {
        var response = BuildResponse(new[]
        {
            new Claim("EmailAddress", "okta@example.com"),
        });

        Assert.Equal("okta@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void Defaults_AreCaseInsensitiveOnClaimType()
    {
        var response = BuildResponse(new[]
        {
            new Claim("EMAIL", "shouty@example.com"),
        });

        Assert.Equal("shouty@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void Defaults_WhitespaceValueSkipsToNextDefault()
    {
        // 'email' (3rd in whitelist) is whitespace; 'mail' (4th) has a real value.
        var response = BuildResponse(new[]
        {
            new Claim("email", "  "),
            new Claim("mail", "real@example.com"),
        });

        Assert.Equal("real@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    // ── 3. NameID fallback path ───────────────────────────────────────────────

    [Fact]
    public void NameId_WithEmailFormat_ReturnsValue()
    {
        var response = BuildResponse(
            claims: null,
            nameIdValue: "user@example.com",
            nameIdFormat: NameIdentifierFormats.Email.OriginalString);

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_FormatCaseInsensitive()
    {
        // The format comparison is OrdinalIgnoreCase, so an upper-case URN must still match.
        var response = BuildResponse(
            claims: null,
            nameIdValue: "user@example.com",
            nameIdFormat: NameIdentifierFormats.Email.OriginalString.ToUpperInvariant());

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_NoFormat_ButValueLooksLikeEmail_Returns()
    {
        // Saml2NameIdentifier(string) ctor leaves Format = null; '@' in value triggers the
        // "looks like an email" branch.
        var response = BuildResponse(claims: null, nameIdValue: "user@example.com");

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_NonEmailFormat_AndNoAtSign_ReturnsNull()
    {
        var response = BuildResponse(
            claims: null,
            nameIdValue: "S-1-5-21-1234",
            nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        Assert.Null(EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_NonEmailFormat_ButValueHasAtSign_Returns()
    {
        // Format isn't 'email' but the value contains '@', so we still return it.
        var response = BuildResponse(
            claims: null,
            nameIdValue: "user@example.com",
            nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        Assert.Equal("user@example.com",
            EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_Null_ReturnsNull()
    {
        // No claims, no NameId.
        var response = BuildResponse(claims: null, nameIdValue: null);

        Assert.Null(EmailAttributeResolver.Resolve(response, Cfg()));
    }

    [Fact]
    public void NameId_WhitespaceValue_ReturnsNull()
    {
        var response = BuildResponse(
            claims: null,
            nameIdValue: "   ",
            nameIdFormat: NameIdentifierFormats.Email.OriginalString);

        Assert.Null(EmailAttributeResolver.Resolve(response, Cfg()));
    }

    // ── 4. Sanity: whitelist surface ──────────────────────────────────────────

    [Fact]
    public void DefaultEmailClaimTypes_ContainsKnownIdpClaims()
    {
        // Cheap guard: if someone removes one of the canonical IdP claim types, this
        // test breaks loudly before integration coverage catches it.
        Assert.Contains("email", EmailAttributeResolver.DefaultEmailClaimTypes);
        Assert.Contains("mail", EmailAttributeResolver.DefaultEmailClaimTypes);
        Assert.Contains("EmailAddress", EmailAttributeResolver.DefaultEmailClaimTypes);
        Assert.Contains("urn:oid:0.9.2342.19200300.100.1.3",
            EmailAttributeResolver.DefaultEmailClaimTypes);
        Assert.Contains("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            EmailAttributeResolver.DefaultEmailClaimTypes);
    }
}
