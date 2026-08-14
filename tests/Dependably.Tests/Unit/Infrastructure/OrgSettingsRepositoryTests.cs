using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers <see cref="OrgSettingsRepository"/> — the settings write path used by
/// <c>OrgSettingsController</c>. Tests all Upsert branches: Clamp(null,*) /
/// Clamp(*,null), DefaultLanguage whitespace handling, and every Upsert's
/// insert + update path. <c>instance_settings</c> listing (including the secret-key
/// exclusion) lives on <see cref="OrgRepository"/>, not this repository — see
/// <c>OrgRepositoryTests</c> for that coverage.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgSettingsRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly OrgSettingsRepository _repo;

    public OrgSettingsRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new OrgSettingsRepository(_fixture.Store);
    }

    // ── GetSettingsAsync ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetSettingsAsync_UnknownOrg_ReturnsNull()
    {
        Assert.Null(await _repo.GetSettingsAsync("does-not-exist"));
    }

    [Fact]
    public async Task GetSettingsAsync_SeededOrg_ReturnsDefaults()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"defaults-{Guid.NewGuid():N}");
        var settings = await _repo.GetSettingsAsync(orgId);
        Assert.NotNull(settings);
        // COALESCE defaults: license_enforcement_mode='off', passthrough=true, tolerance=10.0, lang='en', overwrite=false
        Assert.Equal("off", settings!.LicenseEnforcementMode);
        Assert.True(settings.ProxyPassthroughEnabled);
        Assert.Equal(10.0, settings.MaxOsvScoreTolerance);
        Assert.Equal("en", settings.DefaultLanguage);
        Assert.False(settings.AllowVersionOverwrite);
    }

    // ── UpsertSettingsAsync — Clamp() branch matrix ──────────────────────────

    [Fact]
    public async Task UpsertSettingsAsync_Clamp_OrgValueNull_ReturnsNull()
    {
        // Hits the `if (orgVal is null) return null;` branch of Clamp.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"clamp-orgnull-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: null,
            MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null,
            InstanceMaxUploadBytes: 500_000_000L,
            DefaultLanguage: null));

        var settings = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Null(settings.MaxUploadBytes);
        Assert.Null(settings.MaxUploadBytesPyPi);
        Assert.Null(settings.MaxUploadBytesNpm);
        Assert.Null(settings.MaxUploadBytesNuGet);
    }

    [Fact]
    public async Task UpsertSettingsAsync_Clamp_InstanceMaxNull_PassesOrgValueThrough()
    {
        // Hits the `if (instanceMax is null) return orgVal;` branch of Clamp.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"clamp-instnull-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: true, AllowlistMode: true,
            MaxUploadBytes: 999L,
            MaxUploadBytesPyPi: 111L,
            MaxUploadBytesNpm: 222L,
            MaxUploadBytesNuGet: 333L,
            InstanceMaxUploadBytes: null,
            DefaultLanguage: null));

        var settings = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(999L, settings.MaxUploadBytes);
        Assert.Equal(111L, settings.MaxUploadBytesPyPi);
        Assert.Equal(222L, settings.MaxUploadBytesNpm);
        Assert.Equal(333L, settings.MaxUploadBytesNuGet);
    }

    [Fact]
    public async Task UpsertSettingsAsync_Clamp_BothPresent_TakesMin()
    {
        // Hits the `return Math.Min(orgVal, instanceMax)` branch of Clamp.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"clamp-min-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: 2_000_000_000L,
            MaxUploadBytesPyPi: 100L,                  // < instance, kept
            MaxUploadBytesNpm: 9_999_999_999L,         // > instance, clamped
            MaxUploadBytesNuGet: 500_000_000L,         // == instance, kept
            InstanceMaxUploadBytes: 500_000_000L,
            DefaultLanguage: null));

        var settings = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(500_000_000L, settings.MaxUploadBytes);
        Assert.Equal(100L, settings.MaxUploadBytesPyPi);
        Assert.Equal(500_000_000L, settings.MaxUploadBytesNpm);
        Assert.Equal(500_000_000L, settings.MaxUploadBytesNuGet);
    }

    // ── UpsertSettingsAsync — language + tristate overwrite branches ─────────

    [Fact]
    public async Task UpsertSettingsAsync_WhitespaceLanguage_TreatedAsNull_DefaultsToEn()
    {
        // Hits the `string.IsNullOrWhiteSpace == true` branch (lang collapses to null).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lang-ws-{Guid.NewGuid():N}");
        // First seed a non-en value so we can prove the next call preserves it (COALESCE(@lang, default_language)).
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: "fr"));
        Assert.Equal("fr", (await _repo.GetSettingsAsync(orgId))!.DefaultLanguage);

        // Now pass whitespace — IsNullOrWhiteSpace short-circuits to null, COALESCE preserves "fr".
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: "   "));
        Assert.Equal("fr", (await _repo.GetSettingsAsync(orgId))!.DefaultLanguage);
    }

    [Fact]
    public async Task UpsertSettingsAsync_ConcreteLanguage_StoredVerbatim()
    {
        // Hits the `string.IsNullOrWhiteSpace == false` branch (lang flows through).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lang-set-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: "de"));
        Assert.Equal("de", (await _repo.GetSettingsAsync(orgId))!.DefaultLanguage);
    }

    [Fact]
    public async Task UpsertSettingsAsync_AllowVersionOverwriteFalse_PersistsAsFalse()
    {
        // Hits ToBoolFlag(false) → returns 0. The null case is covered by
        // AirGapped_RoundTripsAndTristateNullPreserves; this test covers the false arm.
        // Then a follow-up call with null preserves false.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ow-false-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AllowVersionOverwrite: true));
        Assert.True((await _repo.GetSettingsAsync(orgId))!.AllowVersionOverwrite);

        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AllowVersionOverwrite: false));
        Assert.False((await _repo.GetSettingsAsync(orgId))!.AllowVersionOverwrite);
    }

    [Fact]
    public async Task UpsertSettingsAsync_InsertPath_OnFreshOrg_FirstWriteCreatesRow()
    {
        // Insert vs update path: insert a brand-new orgs row (no org_settings yet) and
        // verify UpsertSettings creates one. OrgSeeder always pre-creates org_settings,
        // so we craft an org manually to hit the INSERT half of the upsert.
        string orgId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = orgId, slug = $"freshorg-{Guid.NewGuid():N}" });
        }
        Assert.Null(await _repo.GetSettingsAsync(orgId));   // no settings row yet

        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: true, AllowlistMode: true,
            MaxUploadBytes: 42L, null, null, null, null, DefaultLanguage: "en"));

        var settings = await _repo.GetSettingsAsync(orgId);
        Assert.NotNull(settings);
        Assert.Equal(42L, settings!.MaxUploadBytes);
        Assert.True(settings.AnonymousPull);
        Assert.True(settings.AllowlistMode);
    }

    // ── UpsertSettingsAsync — air_gapped round-trip + tristate ───────────────

    [Fact]
    public async Task UpsertSettingsAsync_AirGapped_RoundTripsAndTristateNullPreserves()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"airgap-{Guid.NewGuid():N}");
        // Default: off.
        Assert.False((await _repo.GetSettingsAsync(orgId))!.AirGapped);

        // Set on.
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AirGapped: true));
        Assert.True((await _repo.GetSettingsAsync(orgId))!.AirGapped);

        // null = leave unchanged → stays on (COALESCE(@airGapped, air_gapped)).
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AirGapped: null));
        Assert.True((await _repo.GetSettingsAsync(orgId))!.AirGapped);

        // Explicitly back off.
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AirGapped: false));
        Assert.False((await _repo.GetSettingsAsync(orgId))!.AirGapped);
    }

    [Theory]
    [InlineData(true, false, true)]    // passthrough on, not air-gapped → effective on
    [InlineData(true, true, false)]    // passthrough on, air-gapped     → effective off
    [InlineData(false, false, false)]  // passthrough off                → effective off
    [InlineData(false, true, false)]   // passthrough off + air-gapped   → effective off
    public void ProxyPassthroughEffective_TrueOnlyWhenEnabledAndNotAirGapped(
        bool passthrough, bool airGapped, bool expected)
    {
        var settings = new OrgSettings
        {
            ProxyPassthroughEnabled = passthrough,
            AirGapped = airGapped,
        };
        Assert.Equal(expected, settings.ProxyPassthroughEffective);
    }

    // ── UpsertRetentionAsync ─────────────────────────────────────────────────

    [Fact]
    public async Task UpsertRetentionAsync_InsertThenUpdate_BothPathsHit()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ret-{Guid.NewGuid():N}");
        await _repo.UpsertRetentionAsync(orgId, keepVersions: 10, keepDays: 30, activityRetentionDays: 90,
            purgeUnlistedAfterDays: 45);
        var first = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(10, first.KeepVersions);
        Assert.Equal(30, first.KeepDays);
        Assert.Equal(90, first.ActivityRetentionDays);
        Assert.Equal(45, first.PurgeUnlistedAfterDays);

        // Update path — ON CONFLICT DO UPDATE branch.
        await _repo.UpsertRetentionAsync(orgId, keepVersions: null, keepDays: 7, activityRetentionDays: null,
            purgeUnlistedAfterDays: null);
        var second = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Null(second.KeepVersions);
        Assert.Equal(7, second.KeepDays);
        Assert.Null(second.ActivityRetentionDays);
        Assert.Null(second.PurgeUnlistedAfterDays);
    }

    // ── UpsertProxySettingsAsync ─────────────────────────────────────────────

    [Fact]
    public async Task UpsertProxySettingsAsync_DisableThenReEnable_PersistsBothShapes()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"proxy-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(false, 3.7));
        var disabled = (await _repo.GetSettingsAsync(orgId))!;
        Assert.False(disabled.ProxyPassthroughEnabled);
        Assert.Equal(3.7, disabled.MaxOsvScoreTolerance);

        // Hits the `proxyEnabled ? 1 : 0` true branch — paired with the false case above
        // this closes out the ternary's two arms.
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 8.25));
        var enabled = (await _repo.GetSettingsAsync(orgId))!;
        Assert.True(enabled.ProxyPassthroughEnabled);
        Assert.Equal(8.25, enabled.MaxOsvScoreTolerance);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_MinReleaseAge_NullSetClear_RoundTrips()
    {
        // Tri-state lifecycle (Optional<int?>): a fresh org starts with the policy off (NULL),
        // the operator sets a positive value (present, non-null), then explicitly clears it back
        // to NULL (present, null) — a deliberate clear-to-off, not an omitted field. All three
        // writes must survive a re-read so the UI never shows stale state after a clear.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"minage-{Guid.NewGuid():N}");
        Assert.Null((await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MinReleaseAgeHours: Optional<int?>.Of(48)));
        Assert.Equal(48, (await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MinReleaseAgeHours: Optional<int?>.Of(null)));
        Assert.Null((await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedMinReleaseAgeHours_LeavesStoredValueUnchanged()
    {
        // min_release_age_hours is an enforcing release-age hold, not just a preference. A
        // partial PUT that never mentions it (Optional<int?>.Absent, i.e. the field genuinely
        // absent from the JSON body) must not silently disable it — the tri-state Optional<T>
        // binding is what makes "absent" distinguishable from "explicitly cleared" here, since a
        // plain nullable can only represent one of those two states.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"minage-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MinReleaseAgeHours: Optional<int?>.Of(72)));

        // Second write omits MinReleaseAgeHours entirely (Optional<int?>.Absent, the default).
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 6.5));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(72, after.MinReleaseAgeHours);
        Assert.Equal(6.5, after.MaxOsvScoreTolerance);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedVerifyFields_LeaveStoredValuesUnchanged()
    {
        // A client PUTting a payload shape that predates the verify_* gates (or a CI script
        // toggling one unrelated knob) must not silently downgrade five signature-verification
        // controls to 'off'. Absent means "leave as stored", matching air_gapped / require_mfa.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"verify-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            VerifyNpmSignatures: "block",
            VerifyNuGetSignatures: "block",
            VerifyPyPiAttestations: "warn",
            VerifyRpmSignatures: "block",
            VerifyMavenSignatures: "warn"));

        // Second write omits all five entirely.
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 6.5));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(6.5, after.MaxOsvScoreTolerance);
        Assert.Equal("block", after.VerifyNpmSignatures);
        Assert.Equal("block", after.VerifyNuGetSignatures);
        Assert.Equal("warn", after.VerifyPyPiAttestations);
        Assert.Equal("block", after.VerifyRpmSignatures);
        Assert.Equal("warn", after.VerifyMavenSignatures);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_ExplicitOffVerifyFields_StillTakeEffect()
    {
        // Adversarial twin: leave-unchanged-on-absent must not swallow a deliberate disable.
        // An operator explicitly sending "off" still turns the gate off.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"verify-off-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            VerifyNpmSignatures: "block", VerifyNuGetSignatures: "block"));
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            VerifyNpmSignatures: "off", VerifyNuGetSignatures: "off"));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal("off", after.VerifyNpmSignatures);
        Assert.Equal("off", after.VerifyNuGetSignatures);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_NeverWrittenOrgWithOmittedVerifyFields_ReadsOff()
    {
        // Adversarial twin: with nothing previously stored, absent resolves to the column
        // default rather than writing NULL into a NOT NULL column.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"verify-new-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal("off", after.VerifyNpmSignatures);
        Assert.Equal("off", after.VerifyNuGetSignatures);
        Assert.Equal("off", after.VerifyPyPiAttestations);
        Assert.Equal("off", after.VerifyRpmSignatures);
        Assert.Equal("off", after.VerifyMavenSignatures);
    }

    // ── Absent-field contract: block-gate / passthrough / OSV-tolerance fields ──────────────

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedBlockKev_LeavesStoredValueUnchanged()
    {
        // A partial PUT that never mentions block_kev (e.g. one only touching
        // max_osv_score_tolerance) must leave a previously-enforcing 'block' untouched, matching
        // COALESCE(@blockKev, block_kev) in the ON CONFLICT UPDATE.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"block-kev-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0, BlockKev: "block"));

        // Second write omits BlockKev entirely — models a client PUTting only an unrelated field.
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 6.5));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal("block", after.BlockKev);
        Assert.Equal(6.5, after.MaxOsvScoreTolerance);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedBlockGateFields_LeaveStoredValuesUnchanged()
    {
        // Same coverage as the block_kev case above for every peer column in the block-gate
        // family: block_deprecated, block_revoked, block_malicious, block_install_scripts.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"block-gates-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            BlockDeprecated: "block_all",
            BlockMalicious: "warn",
            BlockInstallScripts: "block",
            BlockRevoked: "block"));

        // Second write omits all four entirely.
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal("block_all", after.BlockDeprecated);
        Assert.Equal("warn", after.BlockMalicious);
        Assert.Equal("block", after.BlockInstallScripts);
        Assert.Equal("block", after.BlockRevoked);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_ExplicitOffBlockGateFields_StillTakeEffect()
    {
        // Adversarial twin: leave-unchanged-on-absent must not swallow a deliberate disable —
        // an operator explicitly turning a gate off still writes 'off'.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"block-gates-off-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            BlockKev: "block", BlockMalicious: "block", BlockInstallScripts: "block", BlockRevoked: "block"));
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0,
            BlockKev: "off", BlockMalicious: "off", BlockInstallScripts: "off", BlockRevoked: "off"));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal("off", after.BlockKev);
        Assert.Equal("off", after.BlockMalicious);
        Assert.Equal("off", after.BlockInstallScripts);
        Assert.Equal("off", after.BlockRevoked);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_NeverWrittenOrgWithOmittedBlockGateFields_ReadsColumnDefaults()
    {
        // Adversarial twin: with nothing previously stored, absent resolves to each column's own
        // default rather than writing NULL into a NOT NULL column.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"block-gates-new-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings());

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.True(after.ProxyPassthroughEnabled);
        Assert.Equal(10.0, after.MaxOsvScoreTolerance);
        Assert.Equal("off", after.BlockDeprecated);
        Assert.Equal("warn", after.BlockRevoked);
        Assert.Equal("block", after.BlockMalicious);
        Assert.Equal("off", after.BlockKev);
        Assert.Equal("off", after.BlockInstallScripts);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedProxyPassthroughEnabled_LeavesStoredValueUnchanged()
    {
        // A partial PUT that omits proxy_passthrough_enabled must not flip an operator's
        // disabled passthrough back on: ProxyPassthroughEnabled is nullable (bool?) precisely so
        // an absent field is distinguishable from an explicit false on the wire.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"passthrough-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(false, 10.0));
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(MaxOsvScoreTolerance: 7.0));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.False(after.ProxyPassthroughEnabled);
        Assert.Equal(7.0, after.MaxOsvScoreTolerance);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_ExplicitFalseProxyPassthroughEnabled_StillTakesEffect()
    {
        // Adversarial twin: explicit false must still disable passthrough, not be swallowed by
        // the leave-unchanged-on-absent fix.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"passthrough-off-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0));
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(false, 10.0));

        Assert.False((await _repo.GetSettingsAsync(orgId))!.ProxyPassthroughEnabled);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedMaxOsvScoreTolerance_LeavesStoredValueUnchanged()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"osv-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 4.2));
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(BlockKev: "block"));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(4.2, after.MaxOsvScoreTolerance);
        Assert.Equal("block", after.BlockKev);
    }

    // ── MinReleaseAgeHours / MaxEpssTolerance: tri-state (Optional<T>) matrix ────────────────
    // Both columns' own "gate disabled" domain state is SQL NULL, so a plain nullable can't tell
    // "the caller omitted this field" apart from "the caller explicitly cleared it". Optional<T>
    // keeps all three states distinguishable: absent (leave unchanged), present + null
    // (deliberate clear-to-off), present + a value (set it). MinReleaseAgeHours' absent
    // and explicit-value/explicit-null coverage lives in the two tests above; this covers the
    // same three states for MaxEpssTolerance.

    [Fact]
    public async Task UpsertProxySettingsAsync_OmittedMaxEpssTolerance_LeavesStoredValueUnchanged()
    {
        // max_epss_tolerance is an enforcing EPSS-ceiling gate. A partial PUT that never
        // mentions it (Optional<double?>.Absent) must not silently disable it — same contract as
        // the min-release-age absent test above.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-keep-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MaxEpssTolerance: Optional<double?>.Of(0.3)));

        // Second write omits MaxEpssTolerance entirely (Optional<double?>.Absent, the default).
        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 6.5));

        var after = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(0.3, after.MaxEpssTolerance);
        Assert.Equal(6.5, after.MaxOsvScoreTolerance);
    }

    [Fact]
    public async Task UpsertProxySettingsAsync_ExplicitNullMaxEpssTolerance_ClearsToNull()
    {
        // Adversarial twin: leave-unchanged-on-absent must not swallow a deliberate clear — an
        // operator explicitly sending null (present, null — not an omitted key) still disables
        // the gate. Also exercises the explicit-value branch on the way in.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-clear-{Guid.NewGuid():N}");

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MaxEpssTolerance: Optional<double?>.Of(0.3)));
        Assert.Equal(0.3, (await _repo.GetSettingsAsync(orgId))!.MaxEpssTolerance);

        await _repo.UpsertProxySettingsAsync(orgId,
            new ProxyPolicySettings(true, 10.0, MaxEpssTolerance: Optional<double?>.Of(null)));
        Assert.Null((await _repo.GetSettingsAsync(orgId))!.MaxEpssTolerance);
    }

    // ── UpsertLicensePolicyModeAsync ─────────────────────────────────────────

    [Fact]
    public async Task UpsertLicensePolicyModeAsync_RoundTrip_InsertThenUpdate()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lpm-{Guid.NewGuid():N}");
        await _repo.UpsertLicensePolicyModeAsync(orgId, "warn");
        Assert.Equal("warn", (await _repo.GetSettingsAsync(orgId))!.LicenseEnforcementMode);
        await _repo.UpsertLicensePolicyModeAsync(orgId, "block");
        Assert.Equal("block", (await _repo.GetSettingsAsync(orgId))!.LicenseEnforcementMode);
    }
}
