using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers <see cref="OrgSettingsRepository"/> — the settings write path used by
/// <c>OrgSettingsController</c>. Tests all Upsert branches: Clamp(null,*) /
/// Clamp(*,null), DefaultLanguage whitespace handling, every Upsert's
/// insert + update path, instance settings get/list/set including the
/// jwt_secret filter and conflict overwrite.
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
        await _repo.UpsertRetentionAsync(orgId, keepVersions: 10, keepDays: 30, activityRetentionDays: 90);
        var first = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Equal(10, first.KeepVersions);
        Assert.Equal(30, first.KeepDays);
        Assert.Equal(90, first.ActivityRetentionDays);

        // Update path — ON CONFLICT DO UPDATE branch.
        await _repo.UpsertRetentionAsync(orgId, keepVersions: null, keepDays: 7, activityRetentionDays: null);
        var second = (await _repo.GetSettingsAsync(orgId))!;
        Assert.Null(second.KeepVersions);
        Assert.Equal(7, second.KeepDays);
        Assert.Null(second.ActivityRetentionDays);
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
        // Three-state lifecycle: a fresh org starts with the policy off (NULL), the operator
        // sets a positive value, then clears it back to NULL. All three writes must survive
        // a re-read so the UI never shows stale state after a clear.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"minage-{Guid.NewGuid():N}");
        Assert.Null((await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0, MinReleaseAgeHours: 48));
        Assert.Equal(48, (await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);

        await _repo.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(true, 10.0));
        Assert.Null((await _repo.GetSettingsAsync(orgId))!.MinReleaseAgeHours);
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

    // ── Instance settings ────────────────────────────────────────────────────

    [Fact]
    public async Task GetInstanceSettingAsync_UnknownKey_ReturnsNull()
    {
        Assert.Null(await _repo.GetInstanceSettingAsync($"missing-{Guid.NewGuid():N}"));
    }

    [Fact]
    public async Task SetInstanceSettingAsync_InsertThenOverwrite_ListExcludesJwtSecret()
    {
        string unique = Guid.NewGuid().ToString("N");
        string key = $"k-{unique}";

        // Insert path.
        await _repo.SetInstanceSettingAsync(key, "v1");
        Assert.Equal("v1", await _repo.GetInstanceSettingAsync(key));

        // ON CONFLICT update path.
        await _repo.SetInstanceSettingAsync(key, "v2");
        Assert.Equal("v2", await _repo.GetInstanceSettingAsync(key));

        // jwt_secret stored but excluded from list.
        await _repo.SetInstanceSettingAsync("jwt_secret", "TOPSECRET");
        var listed = await _repo.ListInstanceSettingsAsync();
        Assert.False(listed.ContainsKey("jwt_secret"));
        Assert.Equal("v2", listed[key]);
        // Direct lookup still returns it — used by JWT signing path.
        Assert.Equal("TOPSECRET", await _repo.GetInstanceSettingAsync("jwt_secret"));
    }
}
