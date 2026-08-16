using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Pins that every <see cref="BlockGateRequest"/> factory carries the actor label through to the
/// record, so a <c>blocked_*</c> row survives revocation of the token that caused it.
///
/// <para>This failure is silent by construction, which is why it needs a test rather than a
/// review. <c>AuditActorLabel</c> is an optional record parameter, so a factory that omits it
/// still compiles, still writes a row, and still renders correctly for a <em>live</em> token —
/// the <c>service_tokens</c> join covers for it. The gap only appears once the token is revoked,
/// which is exactly when nobody is running the test suite. The same shape as the hazard
/// <c>BlockGateRequestConstructionComplianceTests</c> exists for: a field left off a call site
/// does not fail to compile, it defaults to null.</para>
///
/// <para>Caught during review of this change: the <c>blocked_*</c> audit calls already read
/// <c>request.AuditActorLabel</c>, but three of the five factories never set it.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGateActorLabelTests
{
    private static TokenRecord ServiceToken() => new()
    {
        Id = "st-1",
        OrgId = "o1",
        Name = "ci-publish",
        Source = TokenSource.Service,
    };

    private static TokenRecord UserToken() => new()
    {
        Id = "ut-1",
        OrgId = "o1",
        UserId = "u1",
        Source = TokenSource.User,
    };

    private static CacheArtifactServeFacts Facts() => new() { Purl = "pkg:npm/left-pad@1.0.0" };

    [Fact]
    public void For_CarriesTheServiceTokenLabel()
    {
        var req = BlockGateRequest.For(
            "o1", "npm", new PackageVersion { Id = "v1", Purl = "pkg:npm/left-pad@1.0.0" },
            ServiceToken(), settings: null, sourceIp: null);

        Assert.Equal("st-1", req.AuditActorId);
        Assert.Equal(ActorKinds.Service, req.ActorKind);
        Assert.Equal("ci-publish", req.AuditActorLabel);
    }

    [Fact]
    public void ForProxyCacheFacts_CarriesTheServiceTokenLabel()
    {
        var req = BlockGateRequest.ForProxyCacheFacts(
            "o1", "npm", Facts(), ServiceToken(), settings: null, sourceIp: null);

        Assert.Equal("st-1", req.AuditActorId);
        Assert.Equal("ci-publish", req.AuditActorLabel);
    }

    /// <summary>
    /// A user actor must carry no label at all. The label column is service-only precisely
    /// because a user's display name is an email, and both the erasure and retention sweeps
    /// scrub a fixed column list that does not include it.
    /// </summary>
    [Fact]
    public void UserToken_CarriesNoLabel()
    {
        var req = BlockGateRequest.For(
            "o1", "npm", new PackageVersion { Id = "v1", Purl = "pkg:npm/left-pad@1.0.0" },
            UserToken(), settings: null, sourceIp: null);

        Assert.Equal("u1", req.AuditActorId);
        Assert.Equal(ActorKinds.User, req.ActorKind);
        Assert.Null(req.AuditActorLabel);
    }

    [Fact]
    public void AnonymousRequest_CarriesNoActorAndNoLabel()
    {
        var req = BlockGateRequest.ForProxyCacheFacts(
            "o1", "npm", Facts(), token: null, settings: null, sourceIp: null);

        Assert.Null(req.AuditActorId);
        Assert.Null(req.ActorKind);
        Assert.Null(req.AuditActorLabel);
    }

    /// <summary>
    /// The positional-actor factories take the label as its own parameter rather than a
    /// <see cref="TokenRecord"/>, so the trio can drift apart at a caller. These pin that the
    /// value reaches the record.
    /// </summary>
    [Fact]
    public void PositionalActorFactories_ThreadTheLabel()
    {
        var firstFetch = BlockGateRequest.ForProxyFirstFetch(
            "o1", "npm", Facts(),
            userId: "st-1", actorKind: ActorKinds.Service, actorLabel: "ci-publish", sourceIp: null,
            maxOsvScoreTolerance: 10.0, minReleaseAgeHours: null, blockDeprecatedMode: null,
            blockMaliciousMode: null, blockKevMode: null, maxEpssTolerance: null,
            blockInstallScriptsMode: null, verifyProvenanceMode: null,
            blockRevokedMode: null, licenseEnforcementMode: null);
        Assert.Equal("ci-publish", firstFetch.AuditActorLabel);

        var deprecation = BlockGateRequest.ForFirstFetchDeprecation(
            "o1", "npm", "pkg:npm/left-pad@1.0.0",
            userId: "st-1", actorKind: ActorKinds.Service, actorLabel: "ci-publish",
            maxOsvScoreTolerance: 10.0, sourceIp: null, deprecated: "yes",
            blockDeprecatedMode: "block_all");
        Assert.Equal("ci-publish", deprecation.AuditActorLabel);
    }
}
