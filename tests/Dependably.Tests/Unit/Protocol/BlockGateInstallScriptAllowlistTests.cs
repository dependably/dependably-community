using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Integration tests for the install-script allowlist interacting with
/// <see cref="BlockGateService"/>. Verifies the critical scenarios:
///   - An allowlisted package with an install script is served under 'block' mode.
///   - A non-allowlisted package with an install script is still blocked under 'block' mode.
///   - Version-pattern restrictions limit the exemption to matching versions only.
///   - Mixed listing scenario: one allowlisted + one non-allowlisted script package in the
///     same org — only the non-allowlisted one is filtered (partial-failure coverage).
///   - Audit row is written on add/remove of allowlist entries.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGateInstallScriptAllowlistTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly AuditRepository _audit;
    private readonly InstallScriptAllowlistService _allowlistSvc;
    private readonly BlockGateService _sut;

    public BlockGateInstallScriptAllowlistTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _audit = new AuditRepository(_fixture.Store);
        _allowlistSvc = new InstallScriptAllowlistService(
            _fixture.Store,
            new MemoryCache(new MemoryCacheOptions()),
            _clock);
        _sut = new BlockGateService(
            new VulnerabilityRepository(_fixture.Store, _clock),
            _audit,
            new QuarantineRepository(_fixture.Store, _clock),
            _allowlistSvc,
            NullLogger<BlockGateService>.Instance,
            _clock);
    }

    // ── Allowlisted package passes arm 9 ─────────────────────────────────────

    [Fact]
    public async Task AllowlistedPackage_WithInstallScript_IsServedUnderBlockMode()
    {
        // The key regression test: a package on the org's install-script allowlist must
        // not be blocked even when block_install_scripts='block' and HasInstallScript=true.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-allow-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        var req = BaseRequest(orgId, "pkg:npm/esbuild@0.19.0") with
        {
            HasInstallScript = true,
            InstallScriptKind = "npm:postinstall",
            BlockInstallScriptsMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    [Fact]
    public async Task NonAllowlistedPackage_WithInstallScript_IsBlockedUnderBlockMode()
    {
        // Regression guard: a package NOT on the allowlist must still be blocked.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-noallow-{Guid.NewGuid():N}");
        // Add a different package to the allowlist — the tested package is not covered.
        await _allowlistSvc.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        var req = BaseRequest(orgId, "pkg:npm/some-dangerous-pkg@1.0.0") with
        {
            HasInstallScript = true,
            InstallScriptKind = "npm:preinstall",
            BlockInstallScriptsMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    // ── Version-pattern scoping ───────────────────────────────────────────────

    [Fact]
    public async Task AllowlistEntry_WithExactVersion_ServesMatchingVersionOnly()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-exact-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "node-gyp", versionPattern: "10.0.1", createdBy: null);

        // Exact match — served.
        var match = BaseRequest(orgId, "pkg:npm/node-gyp@10.0.1") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "block",
        };
        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(match));

        // Different version — blocked.
        var noMatch = BaseRequest(orgId, "pkg:npm/node-gyp@10.0.2") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "block",
        };
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(noMatch));
    }

    [Fact]
    public async Task AllowlistEntry_WithGlobPattern_ServesMatchingVersionRange()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-glob-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "node-gyp", versionPattern: "10.*", createdBy: null);

        // Within the glob range — served.
        var v10 = BaseRequest(orgId, "pkg:npm/node-gyp@10.1.2") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "block",
        };
        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(v10));

        // Outside the glob range — blocked.
        var v9 = BaseRequest(orgId, "pkg:npm/node-gyp@9.4.0") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "block",
        };
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(v9));
    }

    // ── Mixed partial-failure scenario ────────────────────────────────────────

    [Fact]
    public async Task MixedListing_AllowlistedAndNonAllowlisted_OnlyNonAllowlistedIsBlocked()
    {
        // Critical house-rule scenario: two packages with install scripts in the same org.
        // One is on the allowlist (exempt), the other is not. Both are evaluated in the
        // same 'block' mode session. Only the non-allowlisted one must block.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-mixed-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        var allowedReq = BaseRequest(orgId, "pkg:npm/esbuild@0.20.0") with
        {
            HasInstallScript = true,
            InstallScriptKind = "npm:postinstall",
            BlockInstallScriptsMode = "block",
        };
        var blockedReq = BaseRequest(orgId, "pkg:npm/malicious-sdk@1.0.0") with
        {
            HasInstallScript = true,
            InstallScriptKind = "npm:preinstall",
            BlockInstallScriptsMode = "block",
        };

        // Evaluate both in the same session (same org cache).
        var allowedDecision = await _sut.EvaluateAsync(allowedReq);
        var blockedDecision = await _sut.EvaluateAsync(blockedReq);

        Assert.Equal(BlockDecision.Allowed, allowedDecision);
        Assert.Equal(BlockDecision.Blocked, blockedDecision);

        // Exactly one blocked_install_script row, for the non-allowlisted package.
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    // ── Policy mode guardrails ────────────────────────────────────────────────

    [Fact]
    public async Task AllowlistedPackage_WarnMode_IsAlsoServed()
    {
        // In 'warn' mode the arm never fires regardless; the allowlist is a no-op but must
        // not accidentally cause a block.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-warn-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        var req = BaseRequest(orgId, "pkg:npm/esbuild@0.19.0") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "warn",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
    }

    [Fact]
    public async Task NonAllowlistedPackage_OffMode_IsServedNormally()
    {
        // With policy='off', install-script arm never fires even without an allowlist entry.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-off-{Guid.NewGuid():N}");

        var req = BaseRequest(orgId, "pkg:npm/some-pkg@1.0.0") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "off",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
    }

    // ── Arm priority: allowlist does not override stronger arms ──────────────

    [Fact]
    public async Task AllowlistedPackage_ManualBlock_StillBlocked()
    {
        // The allowlist exemption is arm-9-only. A manual block (arm 1) still wins.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-manual-{Guid.NewGuid():N}");
        await _allowlistSvc.AddAsync(orgId, "npm", "esbuild", versionPattern: null, createdBy: null);

        var req = BaseRequest(orgId, "pkg:npm/esbuild@0.19.0") with
        {
            HasInstallScript = true,
            BlockInstallScriptsMode = "block",
            ManualState = "blocked",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_manual"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    // ── Audit rows on allowlist mutations ─────────────────────────────────────

    [Fact]
    public async Task AddToAllowlist_ThenRemove_StoresEntryAndRemovesIt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"bgal-audit-{Guid.NewGuid():N}");
        // Pass null for created_by; user FK requires a real user row, keeping test self-contained.
        var entry = await _allowlistSvc.AddAsync(orgId, "nuget", "Newtonsoft.Json", "13.*", null);

        // Entry returned with correct fields.
        Assert.Equal("nuget", entry.Ecosystem);
        Assert.Equal("Newtonsoft.Json", entry.Name);
        Assert.Equal("13.*", entry.VersionPattern);
        Assert.Null(entry.CreatedBy);

        // Removing the entry returns 1 row deleted.
        int deleted = await _allowlistSvc.DeleteAsync(orgId, entry.Id);
        Assert.Equal(1, deleted);

        // Package is no longer allowlisted.
        Assert.False(await _allowlistSvc.IsAllowlistedAsync(orgId, "nuget", "Newtonsoft.Json", "13.0.1"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static BlockGateRequest BaseRequest(string orgId, string purl) => new(
        OrgId: orgId,
        Ecosystem: "npm",
        Purl: purl,
        VersionId: Guid.NewGuid().ToString("N"),
        ManualState: null,
        VulnCheckedAt: null,
        UserId: null,
        MaxOsvScoreTolerance: 10.0,
        SourceIp: null);

    private async Task<long> CountActivityAsync(string orgId, string eventType)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = @eventType",
            new { orgId, eventType });
    }
}
