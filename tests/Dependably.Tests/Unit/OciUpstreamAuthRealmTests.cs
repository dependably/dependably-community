using Dependably.Configuration;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The token-exchange realm comes verbatim from the upstream's Www-Authenticate challenge,
/// and the operator-configured credentials are attached to whatever it names — so the realm
/// must be HTTPS and constrained to exactly the upstream's own host (or the
/// operator-pinned TokenEndpoint) before any exchange happens. Otherwise a hostile or
/// MITM'd upstream could harvest the registry credentials.
///
/// Registrable-domain matching is intentionally absent: a challenge that redirects to a
/// sibling domain (e.g. auth.docker.io for registry-1.docker.io) is rejected unless the
/// operator explicitly pins that endpoint via TokenEndpoint.
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
        // For "ghcr.io" a registrable-domain check would produce the bare TLD "io" —
        // sibling .io domains must never qualify.
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

    /// <summary>
    /// Regression: sibling-domain realm that shares a registrable domain with the upstream
    /// host (e.g. auth.docker.io vs registry-1.docker.io) must be rejected when no
    /// TokenEndpoint is pinned. Without the fix, the registrable-domain fallback allowed
    /// a hostile upstream to redirect credentials to attacker-auth.attacker.com by
    /// configuring the upstream host as registry.attacker.com.
    /// </summary>
    [Fact]
    public void SiblingDomainRealm_WithoutPinnedEndpoint_IsRejected()
    {
        // Demonstrates the pre-fix vulnerability: attacker controls registry.attacker.com
        // and returns realm="https://harvest.attacker.com/token". The registrable-domain
        // fallback (parentDomain = "attacker.com") previously allowed this.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://harvest.attacker.com/token", Upstream("registry.attacker.com")));

        // Docker Hub's own sibling-domain pattern is also rejected without a pinned endpoint.
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(
            "https://auth.docker.io/token", Upstream("registry-1.docker.io")));
    }

    /// <summary>
    /// Mixed scenario: two upstreams share the same registrable domain but only one has a
    /// matching pinned endpoint. The pinned one succeeds; the unpinned one fails even though
    /// the realm is on the same parent domain.
    /// </summary>
    [Fact]
    public void MixedUpstreams_PinnedSucceeds_UnpinnedFails()
    {
        const string siblingRealm = "https://auth.docker.io/token";

        var pinnedUpstream = Upstream("registry-1.docker.io", tokenEndpoint: siblingRealm);
        var unpinnedUpstream = Upstream("registry-1.docker.io", tokenEndpoint: null);

        Assert.True(OciUpstreamAuthService.IsTrustedRealm(siblingRealm, pinnedUpstream));
        Assert.False(OciUpstreamAuthService.IsTrustedRealm(siblingRealm, unpinnedUpstream));
    }

    // ── Allowed ───────────────────────────────────────────────────────────────

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
    public void DockerHubRealm_WithPinnedTokenEndpoint_IsAllowed()
    {
        // Docker Hub's auth realm (auth.docker.io) is on a different host than the registry
        // (registry-1.docker.io). Credentials reach it only when the operator explicitly
        // pins the endpoint, making the trust decision auditable and intentional.
        Assert.True(OciUpstreamAuthService.IsTrustedRealm(
            "https://auth.docker.io/token", Upstream(
                "registry-1.docker.io", tokenEndpoint: "https://auth.docker.io/token")));
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
