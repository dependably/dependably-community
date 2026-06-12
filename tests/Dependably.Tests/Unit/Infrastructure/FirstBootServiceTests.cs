using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// FirstBootService runs once per install. Tests cover the "no state → seed" branches in
/// single + multi mode, the "any state exists → no-op" idempotency guard, and the env-var
/// overrides for slug / admin email / admin password.
///
/// Each test uses a fresh InMemoryDbFixture (NOT IClassFixture) so the empty-DB precondition
/// holds — once any other test has seeded an org, the "first boot" branch wouldn't fire.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FirstBootServiceTests
{
    private static async Task<InMemoryDbFixture> NewFixtureAsync()
    {
        var fx = new InMemoryDbFixture();
        await fx.InitializeAsync();
        return fx;
    }

    private static FirstBootService NewSut(InMemoryDbFixture fx, IConfiguration config) =>
        new(fx.Store, config, NullLogger<FirstBootService>.Instance);

    private static IConfiguration Cfg(params (string K, string? V)[] entries) =>
        new ConfigurationBuilder().AddInMemoryCollection(
            entries.Select(e => new KeyValuePair<string, string?>(e.K, e.V))).Build();

    [Fact]
    public async Task RunAsync_EmptyDb_SingleMode_CreatesOrgPlusOwnerPlusJwtSecret()
    {
        await using var fx = await NewFixtureAsync();

        await NewSut(fx, Cfg(
            ("DEPLOYMENT_MODE", "single"),
            ("DEFAULT_TENANT_SLUG", "acme-test"),
            ("FIRST_BOOT_ADMIN_EMAIL", "owner@acme.test"),
            ("FIRST_BOOT_ADMIN_PASSWORD", "BootstrapPass12345"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();

        string? orgSlug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("acme-test", orgSlug);

        var (email, role, mustChange) = await conn.QuerySingleAsync<(string Email, string Role, long MustChange)>(
            "SELECT email AS Email, role AS Role, must_change_password AS MustChange FROM users LIMIT 1");
        Assert.Equal("owner@acme.test", email);
        Assert.Equal("owner", role);
        Assert.Equal(1, mustChange);   // forces rotation since seeded password may have been env-logged

        string? jwt = await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'");
        Assert.False(string.IsNullOrEmpty(jwt));
    }

    [Fact]
    public async Task RunAsync_EmptyDb_MultiMode_CreatesSystemAdminOnly_NoOrgNoUser()
    {
        await using var fx = await NewFixtureAsync();

        await NewSut(fx, Cfg(
            ("DEPLOYMENT_MODE", "multi"),
            ("FIRST_BOOT_SYSTEM_ADMIN_EMAIL", "ops@example.com"),
            ("FIRST_BOOT_SYSTEM_ADMIN_PASSWORD", "OpsPass12345"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orgs"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users"));

        long sysCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM system_admins WHERE email = 'ops@example.com'");
        Assert.Equal(1, sysCount);
    }

    [Fact]
    public async Task RunAsync_AlreadyBootstrapped_NoOp()
    {
        await using var fx = await NewFixtureAsync();
        // Seed any row to disqualify the bootstrap branch.
        await OrgSeeder.InsertAsync(fx.Store, "pre-existing");

        await NewSut(fx, Cfg()).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        // Org count stays at 1 (no second bootstrap org). users stays empty.
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orgs"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users"));
        // JWT secret is not seeded on a no-op run.
        string? jwt = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'");
        Assert.Null(jwt);
    }

    [Fact]
    public async Task RunAsync_SingleMode_DefaultsSlugAndEmail_WhenConfigOmitted()
    {
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg()).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? slug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("default", slug);

        string? email = await conn.ExecuteScalarAsync<string>("SELECT email FROM users LIMIT 1");
        Assert.Equal("admin@dependably.local", email);
    }

    [Fact]
    public async Task RunAsync_LegacyDEFAULT_ORG_SLUG_StillHonoured()
    {
        await using var fx = await NewFixtureAsync();
        // Older deploys set DEFAULT_ORG_SLUG; the newer DEFAULT_TENANT_SLUG takes precedence
        // when both are present.
        await NewSut(fx, Cfg(("DEFAULT_ORG_SLUG", "legacy-slug"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? slug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("legacy-slug", slug);
    }

    [Fact]
    public async Task RunAsync_SeedsInstanceSettingsFromEnvWhenProvided()
    {
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(
            ("MAX_UPLOAD_BYTES", "1048576"),
            ("MAX_UPLOAD_BYTES_PYPI", "524288"),
            ("MAX_UPLOAD_BYTES_NPM", "262144"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        Assert.Equal("1048576", await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes'"));
        Assert.Equal("524288", await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_pypi'"));
        Assert.Equal("262144", await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_npm'"));
        // Unspecified key falls back to the InstanceSettingDefaults baseline so the
        // operator UI never loads blank.
        Assert.Equal(InstanceSettingDefaults.MaxUploadBytesNuGet, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_nuget'"));
    }

    [Fact]
    public async Task RunAsync_SeedsAllSixInstanceSettings_WithDefaults_WhenNoEnvVarsSet()
    {
        // Fresh boot with no env-var overrides — every key the operator sees on
        // /system/settings must be present in instance_settings, with the value
        // from InstanceSettingDefaults. Guards against the UI loading blank.
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg()).RunAsync();

        await using var conn = await fx.Store.OpenAsync();

        Assert.Equal(InstanceSettingDefaults.MaxUploadBytes, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes'"));
        Assert.Equal(InstanceSettingDefaults.MaxUploadBytesPyPi, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_pypi'"));
        Assert.Equal(InstanceSettingDefaults.MaxUploadBytesNpm, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_npm'"));
        Assert.Equal(InstanceSettingDefaults.MaxUploadBytesNuGet, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_nuget'"));
        Assert.Equal(InstanceSettingDefaults.GcSchedule, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'gc_schedule'"));
        Assert.Equal(InstanceSettingDefaults.SiemMaxLookbackDays, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'siem_max_lookback_days'"));
    }

    [Fact]
    public async Task RunAsync_SingleMode_SeedsDefaultUpstreamRegistries_RpmOnlyWhenConfigured()
    {
        await using var fx = await NewFixtureAsync();
        // No Rpm:Upstream set → rpm must NOT be seeded (no default upstream for RPM).
        await NewSut(fx, Cfg()).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        var rows = (await conn.QueryAsync<(string Ecosystem, string Url)>(
            "SELECT ecosystem AS Ecosystem, url AS Url FROM upstream_registry ORDER BY ecosystem")).ToList();

        var map = rows.ToDictionary(r => r.Ecosystem, r => r.Url);
        Assert.Equal("https://pypi.org", map["pypi"]);
        Assert.Equal("https://registry.npmjs.org", map["npm"]);
        Assert.Equal("https://api.nuget.org/v3", map["nuget"]);
        Assert.Equal("https://repo1.maven.org/maven2", map["maven"]);
        Assert.False(map.ContainsKey("rpm"));   // RPM has no default — not seeded
    }

    [Fact]
    public async Task RunAsync_SingleMode_UpstreamConfigOverride_IsSeededInsteadOfDefault()
    {
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(
            ("PyPI:Upstream", "https://pypi.internal.example"),
            ("Rpm:Upstream", "https://rpm.internal.example/repo"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        Assert.Equal("https://pypi.internal.example", await conn.ExecuteScalarAsync<string>(
            "SELECT url FROM upstream_registry WHERE ecosystem = 'pypi'"));
        // Rpm:Upstream set → rpm IS seeded with the configured mirror.
        Assert.Equal("https://rpm.internal.example/repo", await conn.ExecuteScalarAsync<string>(
            "SELECT url FROM upstream_registry WHERE ecosystem = 'rpm'"));
    }

    [Fact]
    public async Task RunAsync_MultiMode_PreferringSystemAdminPasswordOverGenericAdminPassword()
    {
        // The multi-mode system admin password takes precedence over the generic
        // FIRST_BOOT_ADMIN_PASSWORD when both are set.
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(
            ("DEPLOYMENT_MODE", "multi"),
            ("FIRST_BOOT_ADMIN_PASSWORD", "WrongPassword12345"),
            ("FIRST_BOOT_SYSTEM_ADMIN_PASSWORD", "CorrectPass12345"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? hash = await conn.ExecuteScalarAsync<string>(
            "SELECT password_hash FROM system_admins LIMIT 1");
        Assert.True(BCrypt.Net.BCrypt.Verify("CorrectPass12345", hash));
        Assert.False(BCrypt.Net.BCrypt.Verify("WrongPassword12345", hash));
    }

    [Fact]
    public async Task RunAsync_MultiMode_FallsBackToGenericAdminPassword_WhenSystemAdminPasswordOmitted()
    {
        // Covers the second arm of the ?? chain in BootstrapMulti:
        // FIRST_BOOT_SYSTEM_ADMIN_PASSWORD is null → fall through to FIRST_BOOT_ADMIN_PASSWORD.
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(
            ("DEPLOYMENT_MODE", "multi"),
            ("FIRST_BOOT_ADMIN_PASSWORD", "FallbackPass12345"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? hash = await conn.ExecuteScalarAsync<string>(
            "SELECT password_hash FROM system_admins LIMIT 1");
        Assert.True(BCrypt.Net.BCrypt.Verify("FallbackPass12345", hash));
    }

    [Fact]
    public async Task RunAsync_MultiMode_DefaultsSystemAdminEmail_WhenConfigOmitted()
    {
        // Covers the null-arm of `config["FIRST_BOOT_SYSTEM_ADMIN_EMAIL"] ?? "system@dependably.local"`
        // and the random-password arm when no password env var is set at all.
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(("DEPLOYMENT_MODE", "multi"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? email = await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM system_admins LIMIT 1");
        Assert.Equal("system@dependably.local", email);

        // password_hash is populated even with no env override (random fallback path).
        string? hash = await conn.ExecuteScalarAsync<string>(
            "SELECT password_hash FROM system_admins LIMIT 1");
        Assert.False(string.IsNullOrEmpty(hash));
    }

    [Fact]
    public async Task RunAsync_EmptyDb_HeaderMode_CreatesSystemAdminOnly_NoOrgNoUser()
    {
        // header mode is a multi-tenant mode (HeaderTenantResolver); first boot must create
        // a system_admin so operators can reach /api/v1/system/* to manage the instance.
        await using var fx = await NewFixtureAsync();

        await NewSut(fx, Cfg(
            ("DEPLOYMENT_MODE", "header"),
            ("FIRST_BOOT_SYSTEM_ADMIN_EMAIL", "ops@header.example"),
            ("FIRST_BOOT_SYSTEM_ADMIN_PASSWORD", "HeaderPass12345"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM orgs"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users"));

        long sysCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM system_admins WHERE email = 'ops@header.example'");
        Assert.Equal(1, sysCount);
    }

    [Fact]
    public async Task RunAsync_HeaderMode_DefaultsSystemAdminEmail_WhenConfigOmitted()
    {
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg(("DEPLOYMENT_MODE", "header"))).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        string? email = await conn.ExecuteScalarAsync<string>(
            "SELECT email FROM system_admins LIMIT 1");
        Assert.Equal("system@dependably.local", email);

        string? hash = await conn.ExecuteScalarAsync<string>(
            "SELECT password_hash FROM system_admins LIMIT 1");
        Assert.False(string.IsNullOrEmpty(hash));
    }
}
