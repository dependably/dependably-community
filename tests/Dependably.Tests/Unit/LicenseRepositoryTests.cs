using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class LicenseRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private LicenseNormalizer? _normalizer;

    public async Task InitializeAsync()
    {
        var initializer = new SchemaInitializer(_db);
        await initializer.InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'org1')");
        // created_by on the policy tables is a real FK to users, so an author id used in a test
        // has to exist — a dangling one now surfaces as an error rather than being swallowed.
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) " +
            "VALUES ('user-1', 'org1', 'u@example.com', 'x', 'admin')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) " +
            "VALUES ('pkg-1', 'org1', 'pypi', 'test', 'test')");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) " +
            "VALUES ('pvid-1', 'pkg-1', '1.0.0', 'pkg:pypi/test@1.0.0', 'blobs/test'), " +
            "       ('pvid-2', 'pkg-1', '2.0.0', 'pkg:pypi/test@2.0.0', 'blobs/test2')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private LicenseRepository Repo() => new(
        _db, TimeProvider.System,
        _normalizer ??= new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance));

    // ── CheckPolicyAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task CheckPolicy_ModeOff_AlwaysAllowed()
    {
        var repo = Repo();
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "off", ["GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_EmptyLicenses_AlwaysAllowed()
    {
        var repo = Repo();
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", []);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("block")]
    public async Task CheckPolicy_BlocklistedLicense_Blocked(string mode)
    {
        var repo = Repo();
        // MIT is allowlisted so it is satisfied under block mode too; the blocklisted GPL-3.0 is
        // then the concrete offender the check reports in both modes.
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", mode, ["MIT", "GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_WarnMode_NotBlocklisted_Allowed_EvenIfNotOnAllowlist()
    {
        var repo = Repo();
        // allowlist is empty, no blocklist entries — warn mode should not enforce allowlist
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "warn", ["MIT", "Apache-2.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlockMode_AllOnAllowlist_Allowed()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddAllowlistAsync("org1", "Apache-2.0");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT", "Apache-2.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlockMode_LicenseNotOnAllowlist_Blocked()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT", "GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_BlocklistTakesPrecedenceOverAllowlist()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "GPL-3.0");
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_LicenseComparison_IsCaseInsensitive()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "gpl-3.0");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "warn", ["GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        Assert.False(allowed);
    }

    // ── CheckPolicyAsync — the conditional disposition ────────────────────────

    // The load-bearing behaviour change. Before conditional existed, a licence that was not on
    // the allowlist was refused outright in block mode, so this test fails without the change:
    // the artifact 403s rather than serving.
    [Fact]
    public async Task CheckPolicy_ConditionalLicense_ServesAndIsReportedForReview()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional,
            "OK when dynamically linked and not redistributed", null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["LGPL-3.0-only"]);

        Assert.True(verdict.Allowed);
        Assert.Null(verdict.BlockedLicense);
        Assert.True(verdict.IsConditional);
        Assert.Equal(["LGPL-3.0-only"], verdict.ConditionalLicenses);
    }

    // Adversarial twin: an unlisted licence must still be refused in block mode. Without this,
    // a bug that made every leaf satisfy the check would pass the test above.
    [Fact]
    public async Task CheckPolicy_UnlistedLicense_StillBlockedInBlockMode()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["GPL-3.0-only"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("GPL-3.0-only", verdict.BlockedLicense);
        Assert.Empty(verdict.ConditionalLicenses);
    }

    // The blocklist outranks both non-denied postures. A licence somehow carrying a conditional
    // entry AND a block entry is refused — "conditional" never becomes a way to smuggle a
    // blocked licence past the gate.
    [Fact]
    public async Task CheckPolicy_ConditionalAndBlocked_IsBlocked()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);
        await repo.AddBlocklistAsync("org1", "LGPL-3.0-only");

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["LGPL-3.0-only"]);

        Assert.False(verdict.Allowed);
        Assert.Equal("LGPL-3.0-only", verdict.BlockedLicense);
    }

    // A plainly-allowed licence reports nothing to review — the conditional signal must not fire
    // for every artifact once any conditional entry exists.
    [Fact]
    public async Task CheckPolicy_PlainlyAllowed_ReportsNoConditional()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["MIT"]);

        Assert.True(verdict.Allowed);
        Assert.False(verdict.IsConditional);
    }

    // "MIT OR LGPL-3.0-only" with MIT unlisted: the OR is satisfied only by the conditional
    // branch, so the artifact genuinely relies on the condition and must be reported.
    [Fact]
    public async Task CheckPolicy_OrExpression_SatisfiedOnlyByConditionalBranch_IsReported()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["MIT OR LGPL-3.0-only"]);

        Assert.True(verdict.Allowed);
        Assert.Equal(["LGPL-3.0-only"], verdict.ConditionalLicenses);
    }

    // Same expression, but MIT is plainly allowed: the artifact is usable under the
    // unconditional branch, so there is no condition for anyone to review. Reporting it here
    // would bury the real conditional findings under noise from dual-licensed packages.
    [Fact]
    public async Task CheckPolicy_OrExpression_WithUnconditionalBranch_ReportsNothing()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["MIT OR LGPL-3.0-only"]);

        Assert.True(verdict.Allowed);
        Assert.False(verdict.IsConditional);
    }

    // Under an AND every leaf is load-bearing, so a conditional leaf is always reported.
    [Fact]
    public async Task CheckPolicy_AndExpression_WithConditionalLeaf_IsReported()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["MIT AND LGPL-3.0-only"]);

        Assert.True(verdict.Allowed);
        Assert.Equal(["LGPL-3.0-only"], verdict.ConditionalLicenses);
    }

    // Identity normalization applies to conditional entries too: a stored canonical id must match
    // an observed name variant, the same way it does for allow/block entries.
    [Fact]
    public async Task CheckPolicy_ConditionalEntry_NormalizesObservedNameVariant()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "Apache-2.0", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "block", ["Apache License 2.0"]);

        Assert.True(verdict.Allowed);
        Assert.Equal(["Apache-2.0"], verdict.ConditionalLicenses);
    }

    // In 'warn' mode the allowlist is not consulted at all, so a conditional entry changes
    // nothing about whether the licence passes — but it is still named for review.
    [Fact]
    public async Task CheckPolicy_WarnMode_ConditionalStillReported()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional, null, null);

        var verdict = await repo.CheckPolicyAsync("org1", "warn", ["LGPL-3.0-only"]);

        Assert.True(verdict.Allowed);
        Assert.Equal(["LGPL-3.0-only"], verdict.ConditionalLicenses);
    }

    // ── Policy-entry notes ────────────────────────────────────────────────────

    [Fact]
    public async Task AddAllowlist_RoundTripsDispositionAndNote()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "LGPL-3.0-only", LicenseDispositions.Conditional,
            "Fine for internal tooling only", "user-1");

        var entry = Assert.Single(await repo.GetAllowlistAsync("org1"));
        Assert.Equal(LicenseDispositions.Conditional, entry.Disposition);
        Assert.Equal("Fine for internal tooling only", entry.Note);
        Assert.Equal("user-1", entry.CreatedBy);
    }

    // An entry added through the pre-existing two-argument overload must land as 'allowed', so an
    // upgrade cannot silently reclassify anything.
    [Fact]
    public async Task AddAllowlist_LegacyOverload_DefaultsToAllowed()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        var entry = Assert.Single(await repo.GetAllowlistAsync("org1"));
        Assert.Equal(LicenseDispositions.Allowed, entry.Disposition);
        Assert.Null(entry.Note);
    }

    [Fact]
    public async Task AddBlocklist_RoundTripsNote()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0-only", "Copyleft; legal policy 2025-11", "user-1");

        var entry = Assert.Single(await repo.GetBlocklistAsync("org1"));
        Assert.Equal("Copyleft; legal policy 2025-11", entry.Note);
    }

    // Leave-unchanged on absent: editing the disposition alone must not wipe the note, which is
    // the whole reason the update takes an explicit "was the note supplied" flag.
    [Fact]
    public async Task UpdateAllowlist_DispositionOnly_LeavesNoteIntact()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT", LicenseDispositions.Allowed, "keep me", null);

        var updated = await repo.UpdateAllowlistAsync(
            "org1", "MIT", LicenseDispositions.Conditional, noteSet: false, note: null);

        Assert.NotNull(updated);
        Assert.Equal(LicenseDispositions.Conditional, updated.Disposition);
        Assert.Equal("keep me", updated.Note);
    }

    // ...and the converse: supplying an explicit null note clears it, which a plain nullable
    // parameter could not distinguish from "leave it alone".
    [Fact]
    public async Task UpdateAllowlist_ExplicitNullNote_ClearsIt()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT", LicenseDispositions.Allowed, "remove me", null);

        var updated = await repo.UpdateAllowlistAsync(
            "org1", "MIT", disposition: null, noteSet: true, note: null);

        Assert.NotNull(updated);
        Assert.Equal(LicenseDispositions.Allowed, updated.Disposition);
        Assert.Null(updated.Note);
    }

    [Fact]
    public async Task UpdateAllowlist_UnknownLicense_ReturnsNull()
    {
        var repo = Repo();
        Assert.Null(await repo.UpdateAllowlistAsync(
            "org1", "MIT", LicenseDispositions.Conditional, noteSet: false, note: null));
    }

    [Fact]
    public async Task UpdateBlocklist_LeavesNoteIntactWhenAbsent()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0-only", "original", null);

        var updated = await repo.UpdateBlocklistAsync("org1", "GPL-3.0-only", noteSet: false, note: null);

        Assert.NotNull(updated);
        Assert.Equal("original", updated.Note);
    }

    // ── CheckPolicyAsync — compound expressions ───────────────────────────────

    [Fact]
    public async Task CheckPolicy_Compound_Or_OneLeafAllowed_Allowed()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        // Block mode: only MIT is allowlisted, but OR is satisfied by the one allowed leaf.
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT OR GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_Compound_And_OneLeafMissing_Blocked()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        // Block mode: GPL-3.0 is not on the allowlist, so the AND is unsatisfied.
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT AND GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_Compound_BlocklistedOperand_UnderOr_PassesWhenSiblingAllowed()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT OR GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_Compound_BlocklistedOperand_UnderAnd_Blocks()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        // Warn mode: a blocklisted leaf under AND still blocks the whole expression.
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "warn", ["MIT AND GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        Assert.Equal("GPL-3.0", blocked);
    }

    [Fact]
    public async Task CheckPolicy_Compound_BlockVsWarn_UnlistedLeaf()
    {
        var repo = Repo();

        // Warn mode enforces only the blocklist — an unlisted single leaf passes.
        var warnAllowedVerdict = await repo.CheckPolicyAsync("org1", "warn", ["MIT OR GPL-3.0"]);
        bool warnAllowed = warnAllowedVerdict.Allowed;
        Assert.True(warnAllowed);

        // Block mode requires an allowlisted leaf — with an empty allowlist it fails.
        var blockAllowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT OR GPL-3.0"]);
        bool blockAllowed = blockAllowedVerdict.Allowed;
        string? blocked = blockAllowedVerdict.BlockedLicense;
        Assert.False(blockAllowed);
        Assert.Equal("MIT", blocked);
    }

    [Fact]
    public async Task CheckPolicy_NormalizesLicenseNameVariant()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "Apache-2.0");

        // The observed leaf is the human name variant; it must normalize onto the canonical id.
        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["Apache License 2.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.True(allowed);
        Assert.Null(blocked);
    }

    [Fact]
    public async Task CheckPolicy_OffendingLeaf_NamesConcreteLicense_NotWholeExpression()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");

        var allowedVerdict = await repo.CheckPolicyAsync("org1", "block", ["MIT AND GPL-3.0"]);
        bool allowed = allowedVerdict.Allowed;
        string? blocked = allowedVerdict.BlockedLicense;
        Assert.False(allowed);
        // The reason names the concrete failing leaf, never the compound string.
        Assert.Equal("GPL-3.0", blocked);
    }

    // ── SetLicensesAsync / GetForVersionAsync ─────────────────────────────────

    [Fact]
    public async Task SetAndGet_Licenses_RoundTrip()
    {
        var repo = Repo();
        await repo.SetLicensesAsync("pvid-1", ["MIT", "Apache-2.0"], "upstream");

        var results = await repo.GetForVersionAsync("pvid-1");
        var spdxIds = results.Select(r => r.LicenseSpdx).ToHashSet();
        Assert.Contains("MIT", spdxIds);
        Assert.Contains("Apache-2.0", spdxIds);
        Assert.All(results, r => Assert.Equal("upstream", r.Source));
    }

    [Fact]
    public async Task SetLicenses_DuplicateIgnored()
    {
        var repo = Repo();
        await repo.SetLicensesAsync("pvid-2", ["MIT"], "upstream");
        await repo.SetLicensesAsync("pvid-2", ["MIT"], "sbom"); // same SPDX, different source — ON CONFLICT DO NOTHING

        var results = await repo.GetForVersionAsync("pvid-2");
        Assert.Single(results);
    }

    // ── Allowlist CRUD ────────────────────────────────────────────────────────

    [Fact]
    public async Task AddAllowlist_Duplicate_ReturnsNull()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        var second = await repo.AddAllowlistAsync("org1", "MIT");
        Assert.Null(second);
    }

    [Fact]
    public async Task RemoveAllowlist_ExistingEntry_ReturnsTrue()
    {
        var repo = Repo();
        await repo.AddAllowlistAsync("org1", "MIT");
        bool removed = await repo.RemoveAllowlistAsync("org1", "MIT");
        Assert.True(removed);
    }

    [Fact]
    public async Task RemoveAllowlist_NonExistentEntry_ReturnsFalse()
    {
        var repo = Repo();
        bool removed = await repo.RemoveAllowlistAsync("org1", "MIT");
        Assert.False(removed);
    }

    // ── Blocklist CRUD ────────────────────────────────────────────────────────

    [Fact]
    public async Task AddBlocklist_Duplicate_ReturnsNull()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");
        var second = await repo.AddBlocklistAsync("org1", "GPL-3.0");
        Assert.Null(second);
    }

    [Fact]
    public async Task RemoveBlocklist_ExistingEntry_ReturnsTrue()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");
        bool removed = await repo.RemoveBlocklistAsync("org1", "GPL-3.0");
        Assert.True(removed);
    }

    [Fact]
    public async Task GetBlocklist_OrgIsolation()
    {
        var repo = Repo();
        await repo.AddBlocklistAsync("org1", "GPL-3.0");

        var org2List = await repo.GetBlocklistAsync("org2");
        Assert.Empty(org2List);
    }
}
