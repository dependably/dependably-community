using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

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

        var orgSlug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("acme-test", orgSlug);

        var (email, role, mustChange) = await conn.QuerySingleAsync<(string Email, string Role, long MustChange)>(
            "SELECT email AS Email, role AS Role, must_change_password AS MustChange FROM users LIMIT 1");
        Assert.Equal("owner@acme.test", email);
        Assert.Equal("owner", role);
        Assert.Equal(1, mustChange);   // forces rotation since seeded password may have been env-logged

        var jwt = await conn.ExecuteScalarAsync<string>(
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

        var sysCount = await conn.ExecuteScalarAsync<long>(
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
        var jwt = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'jwt_secret'");
        Assert.Null(jwt);
    }

    [Fact]
    public async Task RunAsync_SingleMode_DefaultsSlugAndEmail_WhenConfigOmitted()
    {
        await using var fx = await NewFixtureAsync();
        await NewSut(fx, Cfg()).RunAsync();

        await using var conn = await fx.Store.OpenAsync();
        var slug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
        Assert.Equal("default", slug);

        var email = await conn.ExecuteScalarAsync<string>("SELECT email FROM users LIMIT 1");
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
        var slug = await conn.ExecuteScalarAsync<string>("SELECT slug FROM orgs LIMIT 1");
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
        // Unspecified key remains unset.
        var nuget = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'max_upload_bytes_nuget'");
        Assert.Null(nuget);
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
        var hash = await conn.ExecuteScalarAsync<string>(
            "SELECT password_hash FROM system_admins LIMIT 1");
        Assert.True(BCrypt.Net.BCrypt.Verify("CorrectPass12345", hash));
        Assert.False(BCrypt.Net.BCrypt.Verify("WrongPassword12345", hash));
    }
}
