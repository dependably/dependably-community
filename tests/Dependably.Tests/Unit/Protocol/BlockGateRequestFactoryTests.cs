using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Verifies that <see cref="BlockGateRequest.For"/> produces a request that is field-identical
/// to a manually constructed <see cref="BlockGateRequest"/> for every combination of token
/// nullability and settings nullability used across the download controllers.
///
/// The factory must not silently drop any field — a missing field would let a policy arm
/// behave as if that setting is off even when the org has it configured.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGateRequestFactoryTests
{
    private readonly DateTimeOffset _now = TestTime.KnownNow;

    // ── nullable token (proxy path) ───────────────────────────────────────────

    [Fact]
    public void For_NullToken_NonNullSettings_MatchesManualConstruction()
    {
        var version = MakeVersion();
        var settings = MakeSettings();
        const string orgId = "org-abc";
        const string ecosystem = "npm";
        const string sourceIp = "10.0.0.1";

        var factory = BlockGateRequest.For(orgId, ecosystem, version, token: null, settings, sourceIp);

        var manual = new BlockGateRequest(orgId, ecosystem, version.Purl, version.Id,
            version.ManualBlockState, version.VulnCheckedAt,
            null, settings.MaxOsvScoreTolerance, sourceIp,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            PublishedAt: version.PublishedAt,
            ActorKind: null,
            Deprecated: version.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            Origin: version.Origin,
            HasInstallScript: version.HasInstallScript,
            InstallScriptKind: version.InstallScriptKind,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            RevokedAt: version.RevokedAt,
            BlockRevokedMode: settings.BlockRevoked);

        Assert.Equal(manual, factory);
    }

    // ── non-null token (hosted path) ──────────────────────────────────────────

    [Fact]
    public void For_NonNullToken_NonNullSettings_MatchesManualConstruction()
    {
        var version = MakeVersion();
        var settings = MakeSettings();
        var token = MakeToken();
        const string orgId = "org-def";
        const string ecosystem = "nuget";
        const string sourceIp = "192.168.1.2";

        var factory = BlockGateRequest.For(orgId, ecosystem, version, token, settings, sourceIp);

        var manual = new BlockGateRequest(orgId, ecosystem, version.Purl, version.Id,
            version.ManualBlockState, version.VulnCheckedAt,
            token.UserId, settings.MaxOsvScoreTolerance, sourceIp,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            PublishedAt: version.PublishedAt,
            ActorKind: token.ActorKind,
            Deprecated: version.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            Origin: version.Origin,
            HasInstallScript: version.HasInstallScript,
            InstallScriptKind: version.InstallScriptKind,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            RevokedAt: version.RevokedAt,
            BlockRevokedMode: settings.BlockRevoked);

        Assert.Equal(manual, factory);
    }

    // ── null settings (Maven-like nullable settings path) ─────────────────────

    [Fact]
    public void For_NullSettings_FallsBackToDefaultTolerance()
    {
        var version = MakeVersion();
        var token = MakeToken();
        const string orgId = "org-ghi";
        const string ecosystem = "maven";
        const string sourceIp = "172.16.0.5";

        var factory = BlockGateRequest.For(orgId, ecosystem, version, token, settings: null, sourceIp);

        // Null settings → tolerance defaults to 10.0, all policy fields null.
        var manual = new BlockGateRequest(orgId, ecosystem, version.Purl, version.Id,
            version.ManualBlockState, version.VulnCheckedAt,
            token.UserId, 10.0, sourceIp,
            MinReleaseAgeHours: null,
            PublishedAt: version.PublishedAt,
            ActorKind: token.ActorKind,
            Deprecated: version.Deprecated,
            BlockDeprecatedMode: null,
            BlockMaliciousMode: null,
            BlockKevMode: null,
            MaxEpssTolerance: null,
            Origin: version.Origin,
            HasInstallScript: version.HasInstallScript,
            InstallScriptKind: version.InstallScriptKind,
            BlockInstallScriptsMode: null,
            RevokedAt: version.RevokedAt,
            BlockRevokedMode: null);

        Assert.Equal(manual, factory);
    }

    // ── mixed partial-failure: batch evaluation with factory requests ─────────
    //
    // Simulates the download-path pattern: a list of (version, token) pairs is
    // evaluated in a loop. Some pass the gate, some are blocked. The factory must
    // produce a request that drives the same block decision as the manual form
    // for each entry — a field omission would cause a version that should be
    // blocked (e.g. manually blocked) to pass through instead.

    [Fact]
    public void For_BatchEvaluation_PartialFailure_FactoryMatchesManualDecision()
    {
        // Arrange two versions: one manually blocked, one allowed.
        var blockedVersion = MakeVersion();
        blockedVersion.ManualBlockState = "blocked";
        var allowedVersion = MakeVersion();
        allowedVersion.ManualBlockState = null;
        var settings = MakeSettings();
        const string orgId = "org-batch";
        const string ecosystem = "pypi";

        // Build requests via factory and via manual construction for both versions.
        var factoryBlocked = BlockGateRequest.For(orgId, ecosystem, blockedVersion, null, settings, null);
        var manualBlocked = new BlockGateRequest(orgId, ecosystem, blockedVersion.Purl, blockedVersion.Id,
            blockedVersion.ManualBlockState, blockedVersion.VulnCheckedAt,
            null, settings.MaxOsvScoreTolerance, null,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            PublishedAt: blockedVersion.PublishedAt,
            ActorKind: null,
            Deprecated: blockedVersion.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            Origin: blockedVersion.Origin,
            HasInstallScript: blockedVersion.HasInstallScript,
            InstallScriptKind: blockedVersion.InstallScriptKind,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            RevokedAt: blockedVersion.RevokedAt,
            BlockRevokedMode: settings.BlockRevoked);

        var factoryAllowed = BlockGateRequest.For(orgId, ecosystem, allowedVersion, null, settings, null);
        var manualAllowed = new BlockGateRequest(orgId, ecosystem, allowedVersion.Purl, allowedVersion.Id,
            allowedVersion.ManualBlockState, allowedVersion.VulnCheckedAt,
            null, settings.MaxOsvScoreTolerance, null,
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            PublishedAt: allowedVersion.PublishedAt,
            ActorKind: null,
            Deprecated: allowedVersion.Deprecated,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            Origin: allowedVersion.Origin,
            HasInstallScript: allowedVersion.HasInstallScript,
            InstallScriptKind: allowedVersion.InstallScriptKind,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            RevokedAt: allowedVersion.RevokedAt,
            BlockRevokedMode: settings.BlockRevoked);

        // Assert: factory requests are field-identical to manual — mixed results
        // (one blocked, one allowed) confirm both paths are covered.
        Assert.Equal(manualBlocked, factoryBlocked);
        Assert.Equal(manualAllowed, factoryAllowed);

        // Verify the blocked version's ManualState flows through and would trigger
        // the blocked arm (pure policy evaluation, no DB needed).
        Assert.Equal("blocked", factoryBlocked.ManualState);
        Assert.Null(factoryAllowed.ManualState);
    }

    // ── null source IP (Maven uses HttpContext.GetNormalizedRemoteIp() inline) ─

    [Fact]
    public void For_NullSourceIp_PropagatesAsNull()
    {
        var version = MakeVersion();
        var settings = MakeSettings();

        var factory = BlockGateRequest.For("org-j", "maven", version, null, settings, sourceIp: null);

        Assert.Null(factory.SourceIp);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private PackageVersion MakeVersion() => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        PackageId = Guid.NewGuid().ToString("N"),
        Version = "1.2.3",
        Purl = $"pkg:npm/test@1.2.3",
        BlobKey = "npm/test/1.2.3/test-1.2.3.tgz",
        SizeBytes = 1024,
        ManualBlockState = null,
        VulnCheckedAt = _now.AddHours(-1),
        Deprecated = null,
        PublishedAt = _now.AddDays(-10),
        Origin = "hosted",
        HasInstallScript = true,
        InstallScriptKind = "npm:postinstall",
    };

    private static OrgSettings MakeSettings() => new()
    {
        MaxOsvScoreTolerance = 7.5,
        MinReleaseAgeHours = 48,
        BlockDeprecated = "warn",
        BlockMalicious = "block",
        BlockKev = "off",
        MaxEpssTolerance = 0.5,
        BlockInstallScripts = "block",
    };

    private static TokenRecord MakeToken() => new()
    {
        UserId = "u1",
        OrgId = "org-abc",
        Capabilities = "[\"read:artifact\"]",
        Source = TokenSource.User,
    };
}
