using Dependably.Configuration;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The token-exchange realm comes verbatim from the upstream's Www-Authenticate challenge,
/// and the operator-configured credentials are attached to whatever it names — so the realm
/// must be HTTPS and constrained to the upstream's own host / registrable domain (or the
/// operator-pinned TokenEndpoint) before any exchange happens. Otherwise a hostile or
/// MITM'd upstream could harvest the registry credentials.
/// </summary>
[Trait("Category", "Unit")]
public class OciUpstreamAuthRealmTests
{
    private static OciUpstreamRegistryOptions Upstream(string host, string? tokenEndpoint = null) => new()
    {
        Name = "test",
        Host = host,
        AuthType = OciAuthType.DockerHubTokenExchange,
        TokenEndpoint = tokenEndpoint,
    };

    // ── Rejections ────────────────────────────────────────────────────────────

    [Fact]
    public void HttpRealm_IsRejected()
    {
        // Plain-HTTP realm would send Basic credentials in cleartext — always refused,
        // even when the host would otherwise match.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "http://auth.docker.io/token", Upstream("registry-1.docker.io")));
    }

    [Fact]
    public void RealmOnUnrelatedHost_IsRejected()
    {
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://attacker.example.net/token", Upstream("registry-1.docker.io")));
    }

    [Fact]
    public void RealmOnSuffixSpoofHost_IsRejected()
    {
        // "notdocker.io" ends with "docker.io" as a raw string but is a different
        // registrable domain — the match must be label-aligned.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://notdocker.io/token", Upstream("registry-1.docker.io")));
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://evil-docker.io/token", Upstream("registry-1.docker.io")));
    }

    [Fact]
    public void TwoLabelUpstreamHost_DoesNotDegradeToTldMatch()
    {
        // For "ghcr.io" the parent would be the bare TLD "io" — sibling .io domains must
        // never qualify.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://evil.io/token", Upstream("ghcr.io")));
    }

    [Fact]
    public void RelativeOrMalformedRealm_IsRejected()
    {
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "/token", Upstream("registry-1.docker.io")));
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "not a url", Upstream("registry-1.docker.io")));
    }

    [Fact]
    public void TokenEndpointMismatch_StaysRejected()
    {
        // A pinned endpoint allows exactly that URL — not the whole foreign domain.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://auth.partner.example/other-path", Upstream(
                "registry.internal.example", tokenEndpoint: "https://auth.partner.example/token")));
    }

    // ── Allowed ───────────────────────────────────────────────────────────────

    [Fact]
    public void DockerHubRealm_ForDockerHubRegistry_IsAllowed()
    {
        // Docker Hub's challenge realm (auth.docker.io) is a sibling of the registry host
        // (registry-1.docker.io) under the same registrable domain — must keep working.
        Assert.True(OciUpstreamAuthService.IsTrustedRealm(
            "https://auth.docker.io/token", Upstream("registry-1.docker.io")));
    }

    [Fact]
    public void RealmOnUpstreamsOwnHost_IsAllowed()
    {
        Assert.True(OciUpstreamAuthService.IsTrustedRealm(
            "https://ghcr.io/token", Upstream("ghcr.io")));
    }

    [Fact]
    public void RealmOnUpstreamsOwnHost_WithConfiguredPort_IsAllowed()
    {
        Assert.True(OciUpstreamAuthService.IsTrustedRealm(
            "https://registry.internal.example/token", Upstream("registry.internal.example:5000")));
    }

    [Fact]
    public void ConfiguredTokenEndpointRealm_OnForeignDomain_IsAllowed()
    {
        // Operator escape hatch for registries whose auth realm lives on a different domain.
        Assert.True(OciUpstreamAuthService.IsTrustedRealm(
            "https://auth.partner.example/token", Upstream(
                "registry.internal.example", tokenEndpoint: "https://auth.partner.example/token")));
    }

    [Fact]
    public void HttpRealm_MatchingTokenEndpoint_StaysRejected()
    {
        // HTTPS is non-negotiable: even an operator-pinned endpoint never sends
        // credentials over cleartext.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "http://auth.partner.example/token", Upstream(
                "registry.internal.example", tokenEndpoint: "http://auth.partner.example/token")));
    }
}
