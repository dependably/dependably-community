using System.Xml;

namespace Dependably.Infrastructure.Saml;

/// <summary>
/// The SP's own, explicit statement of the one property that makes a SAML assertion worth
/// anything: it was signed.
///
/// <para><b>Why this exists as our code rather than as configuration.</b>
/// <c>Saml2Configuration</c> exposes no "require a signature" switch for the validation path —
/// <c>WantAssertionsSigned</c> on the published SP metadata is a declaration to the IdP with no
/// effect here, and <c>AuthnResponseSignType</c> governs responses the library <em>creates</em>.
/// Rejecting an unsigned response is therefore behaviour of <c>ITfoxtec.Identity.Saml2</c>'s
/// <c>Unbind</c>, correct today and asserted nowhere in this repository. A dependency bump that
/// relaxed it would ship green, and the failure mode is a forged assertion minting a session for
/// any account in any tenant. This check states the requirement in the SP's own code so the
/// enforcement does not rest on a third party's default, and the ACS tests pin both halves: an
/// unsigned response and a response signed by an unpinned key are each refused.</para>
///
/// <para><b>What it does and does not prove.</b> Presence is a precondition, not a verification:
/// whether a present signature is <em>valid</em>, covers the assertion that was consumed, and
/// chains to the tenant's pinned certificate stays with the library's <c>ValidateXmlSignature</c>,
/// which runs on the same document immediately afterwards. The two checks fail closed
/// independently — the strictly weaker one is ours, so a library that stopped enforcing the
/// stronger one cannot silently downgrade the SP to accepting a bare, unsigned assertion.</para>
/// </summary>
public static class SamlSignaturePolicy
{
    /// <summary>The XML Digital Signature namespace SAML signatures are carried in.</summary>
    public const string XmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <summary>
    /// True when <paramref name="document"/> carries at least one XML-DSig <c>Signature</c>
    /// element, at any depth — on the response element, on the assertion, or both; SAML allows a
    /// signature at either level and the SP accepts either. A null or empty document is
    /// <em>not</em> signed: an unreadable response never counts as satisfying a security
    /// precondition.
    /// </summary>
    public static bool HasXmlSignature(XmlDocument? document) =>
        document?.DocumentElement is { } root
        && root.GetElementsByTagName("Signature", XmlDsigNamespace).Count > 0;
}
