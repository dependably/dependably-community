namespace Dependably.Infrastructure.Saml;

/// <summary>
/// Shared claim-type sentinel for the SAML test-run "attributes seen" record. The NameID is
/// not itself a claim in <c>ClaimsIdentity.Claims</c>, but the admin needs to see it alongside
/// the real claims when reviewing a test run — so it is persisted as a synthetic entry in the
/// same JSON blob rather than reflected into the <c>/saml-test-result</c> redirect URL (which
/// would echo assertion-controlled data straight into a browser-rendered page). Consumers that
/// display <c>last_test_claims</c> to an admin should filter this sentinel out of the "real
/// claims" list and surface it as its own field instead — see
/// <c>OrgAuthConfigController.Get</c>.
/// </summary>
public static class SamlTestClaimTypes
{
    public const string NameId = "dependably:nameid";
}
