using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The display-timezone preference and its resolution chain. The chain is the load-bearing
/// part: a per-user NULL has to keep meaning "inherit", so that changing the org default
/// reaches every user who never chose a zone. Storing the inherited zone by name instead
/// would pin each user at the value that happened to be current when they last saved.
/// </summary>
[Trait("Category", "Unit")]
public class TimeZonePreferenceTests
{
    [Theory]
    [InlineData("America/Toronto")]
    [InlineData("Europe/Paris")]
    [InlineData("Asia/Tokyo")]
    [InlineData("UTC")]
    public void RecognisesIanaZones(string id) => Assert.True(TimeZoneCodes.IsSupported(id));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Not/AZone")]
    [InlineData("EST5EDT-nonsense")]
    public void RejectsUnrecognisedZones(string? id) => Assert.False(TimeZoneCodes.IsSupported(id));

    [Fact]
    public void UserOverrideWinsOverOrgDefault() =>
        Assert.Equal("Asia/Tokyo", TimeZoneCodes.ResolveEffective("Asia/Tokyo", "Europe/Paris"));

    [Fact]
    public void OrgDefaultAppliesWhenUserHasNoOverride() =>
        Assert.Equal("Europe/Paris", TimeZoneCodes.ResolveEffective(null, "Europe/Paris"));

    [Fact]
    public void FallsBackToUtcWhenNeitherIsSet() =>
        Assert.Equal("UTC", TimeZoneCodes.ResolveEffective(null, null));

    [Fact]
    public void FallsBackRatherThanTrustingAnUnrecognisedStoredValue()
    {
        // A zone removed from the tz database, or a value written before validation existed,
        // must not propagate to Intl as-is.
        Assert.Equal("Europe/Paris", TimeZoneCodes.ResolveEffective("Not/AZone", "Europe/Paris"));
        Assert.Equal("UTC", TimeZoneCodes.ResolveEffective("Not/AZone", "Also/Bogus"));
    }

    [Fact]
    public async Task PersistsTheOverrideAndClearsItBackToInherit()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = Guid.NewGuid().ToString("N");
        string userId = Guid.NewGuid().ToString("N");
        await using (var seed = await db.OpenAsync())
        {
            await seed.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@orgId, 'probe')", new { orgId });
            await seed.ExecuteAsync(
                """
                INSERT INTO org_settings (org_id, default_timezone) VALUES (@orgId, 'Europe/Paris')
                """,
                new { orgId });
            await seed.ExecuteAsync(
                """
                INSERT INTO users (id, tenant_id, email, password_hash)
                VALUES (@userId, @orgId, 'probe@example.test', 'x')
                """,
                new { userId, orgId });
        }

        var users = new UserService(db, new OrgRepository(db));

        // No override yet: the org default is what resolves.
        var inherited = await users.GetUserContextAsync(userId, orgId);
        Assert.Null(inherited!.Timezone);
        Assert.Equal("Europe/Paris", inherited.TenantDefaultTimezone);
        Assert.Equal("Europe/Paris", TimeZoneCodes.ResolveEffective(inherited.Timezone, inherited.TenantDefaultTimezone));

        await users.UpdateTimezoneAsync(userId, "Asia/Tokyo");
        var overridden = await users.GetUserContextAsync(userId, orgId);
        Assert.Equal("Asia/Tokyo", overridden!.Timezone);
        Assert.Equal("Asia/Tokyo", TimeZoneCodes.ResolveEffective(overridden.Timezone, overridden.TenantDefaultTimezone));

        // Clearing restores inheritance rather than freezing the previously resolved zone.
        await users.UpdateTimezoneAsync(userId, null);
        var cleared = await users.GetUserContextAsync(userId, orgId);
        Assert.Null(cleared!.Timezone);
        Assert.Equal("Europe/Paris", TimeZoneCodes.ResolveEffective(cleared.Timezone, cleared.TenantDefaultTimezone));
    }
}
