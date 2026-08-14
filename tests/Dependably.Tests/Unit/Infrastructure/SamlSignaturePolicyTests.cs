using System.Xml;
using Dependably.Infrastructure.Saml;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit coverage for the SP-side signature precondition. The end-to-end refusals live in
/// <c>SamlAcsHardeningTests</c>; those pass whether the precondition or the SAML library does the
/// rejecting, so they cannot tell whether this check still works. These can: each case here fails
/// the moment <see cref="SamlSignaturePolicy.HasXmlSignature"/> stops discriminating.
/// </summary>
public sealed class SamlSignaturePolicyTests
{
    private const string Dsig = SamlSignaturePolicy.XmlDsigNamespace;
    private const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";

    private static XmlDocument Parse(string xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        return doc;
    }

    [Fact]
    public void ResponseWithNoSignature_IsNotSigned()
    {
        var doc = Parse($"""
            <samlp:Response xmlns:samlp="{Protocol}" xmlns:saml="{Assertion}">
              <saml:Assertion><saml:Subject /></saml:Assertion>
            </samlp:Response>
            """);

        Assert.False(SamlSignaturePolicy.HasXmlSignature(doc));
    }

    [Fact]
    public void SignatureOnTheResponseElement_IsSigned()
    {
        var doc = Parse($"""
            <samlp:Response xmlns:samlp="{Protocol}" xmlns:saml="{Assertion}" xmlns:ds="{Dsig}">
              <ds:Signature><ds:SignatureValue>x</ds:SignatureValue></ds:Signature>
              <saml:Assertion><saml:Subject /></saml:Assertion>
            </samlp:Response>
            """);

        Assert.True(SamlSignaturePolicy.HasXmlSignature(doc));
    }

    [Fact]
    public void SignatureOnTheAssertionOnly_IsSigned()
    {
        // SAML permits signing the assertion instead of the response; both shapes are in the
        // field, so the precondition looks at any depth rather than only the document element.
        var doc = Parse($"""
            <samlp:Response xmlns:samlp="{Protocol}" xmlns:saml="{Assertion}" xmlns:ds="{Dsig}">
              <saml:Assertion>
                <ds:Signature><ds:SignatureValue>x</ds:SignatureValue></ds:Signature>
              </saml:Assertion>
            </samlp:Response>
            """);

        Assert.True(SamlSignaturePolicy.HasXmlSignature(doc));
    }

    [Fact]
    public void SignatureElementInAnotherNamespace_IsNotSigned()
    {
        // An element merely named "Signature" is not an XML-DSig signature. Matching on the local
        // name alone would let an attacker satisfy the precondition with an empty decoy element.
        var doc = Parse($"""
            <samlp:Response xmlns:samlp="{Protocol}" xmlns:evil="urn:example:not-dsig">
              <evil:Signature>anything</evil:Signature>
            </samlp:Response>
            """);

        Assert.False(SamlSignaturePolicy.HasXmlSignature(doc));
    }

    [Fact]
    public void NullOrEmptyDocument_IsNotSigned()
    {
        Assert.False(SamlSignaturePolicy.HasXmlSignature(null));
        Assert.False(SamlSignaturePolicy.HasXmlSignature(new XmlDocument()));
    }
}
