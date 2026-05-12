using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class OrgRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly OrgRepository _repo;

    public OrgRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new OrgRepository(_fixture.Store);
    }

    // ── Get / soft-delete cycle ──────────────────────────────────────────────

    [Fact]
    public async Task GetBySlugAsync_RespectsSoftDeleteByDefault_AndOptInToInclude()
    {
        var slug = $"acme-{Guid.NewGuid():N}";
        var id = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        await _repo.SoftDeleteOrgAsync(id);

        Assert.Null(await _repo.GetBySlugAsync(slug));
        var includeDeleted = await _repo.GetBySlugAsync(slug, includeDeleted: true);
        Assert.NotNull(includeDeleted);
        Assert.NotNull(includeDeleted!.DeletedAt);
    }

    [Fact]
    public async Task RestoreOrgAsync_OnlyRestoresActuallyDeletedRows()
    {
        var id = await OrgSeeder.InsertAsync(_fixture.Store, $"acme-{Guid.NewGuid():N}");

        // Not-yet-soft-deleted: RestoreOrgAsync is a no-op (returns false).
        Assert.False(await _repo.RestoreOrgAsync(id));

        await _repo.SoftDeleteOrgAsync(id);
        Assert.True(await _repo.RestoreOrgAsync(id));
        Assert.False(await _repo.RestoreOrgAsync(id));   // already-active row → still false
    }

    [Fact]
    public async Task ListExpiredSoftDeletedOrgIdsAsync_FiltersByGraceWindow()
    {
        var freshId = await OrgSeeder.InsertAsync(_fixture.Store, $"fresh-{Guid.NewGuid():N}");
        var staleId = await OrgSeeder.InsertAsync(_fixture.Store, $"stale-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(freshId);

        // Force the stale one's deleted_at to 60 days ago.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            var sixtyDaysAgo = DateTimeOffset.UtcNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ");
            await conn.ExecuteAsync(
                "UPDATE orgs SET deleted_at = @t WHERE id = @id", new { t = sixtyDaysAgo, id = staleId });
        }

        var expired = await _repo.ListExpiredSoftDeletedOrgIdsAsync(graceDays: 30);
        Assert.Contains(staleId, expired);
        Assert.DoesNotContain(freshId, expired);
    }

    // ── ListOrgsAsync — pagination + includeDeleted ──────────────────────────

    [Fact]
    public async Task ListOrgsAsync_IncludeDeletedFlag_Toggles_DeletedRows()
    {
        var aliveId   = await OrgSeeder.InsertAsync(_fixture.Store, $"alive-{Guid.NewGuid():N}");
        var deletedId = await OrgSeeder.InsertAsync(_fixture.Store, $"deleted-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(deletedId);

        var withDeleted = await _repo.ListOrgsAsync(limit: 100, offset: 0, includeDeleted: true);
        Assert.Contains(withDeleted.Items, o => o.Id == aliveId);
        Assert.Contains(withDeleted.Items, o => o.Id == deletedId);

        var activeOnly = await _repo.ListOrgsAsync(limit: 100, offset: 0, includeDeleted: false);
        Assert.Contains(activeOnly.Items, o => o.Id == aliveId);
        Assert.DoesNotContain(activeOnly.Items, o => o.Id == deletedId);
    }

    // ── Create + Settings ────────────────────────────────────────────────────

    [Fact]
    public async Task CreateOrgAsync_AlsoSeedsOrgSettingsRow()
    {
        var org = await _repo.CreateOrgAsync($"newco-{Guid.NewGuid():N}");
        var settings = await _repo.GetSettingsAsync(org.Id);
        Assert.NotNull(settings);
        Assert.Equal("off", settings!.LicenseEnforcementMode);
    }

    [Fact]
    public async Task UpsertSettingsAsync_ClampsOrgLimitToInstanceLimit()
    {
        var orgId = await _repo.CreateOrgAsync($"o-{Guid.NewGuid():N}");
        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId.Id,
            AnonymousPull: true, AllowlistMode: false,
            MaxUploadBytes: 1_000_000_000L,
            MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null, MaxUploadBytesNuGet: null,
            InstanceMaxUploadBytes: 500_000_000L,
            DefaultLanguage: null));

        var settings = (await _repo.GetSettingsAsync(orgId.Id))!;
        Assert.Equal(500_000_000L, settings.MaxUploadBytes);
        Assert.True(settings.AnonymousPull);
    }

    [Fact]
    public async Task UpsertSettingsAsync_AllowVersionOverwriteNull_PreservesPriorValue()
    {
        // Tristate behaviour: null AllowVersionOverwrite means "don't touch".
        var org = await _repo.CreateOrgAsync($"o-{Guid.NewGuid():N}");

        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            org.Id, AnonymousPull: false, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AllowVersionOverwrite: true));
        Assert.True((await _repo.GetSettingsAsync(org.Id))!.AllowVersionOverwrite);

        await _repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            org.Id, AnonymousPull: true, AllowlistMode: false,
            null, null, null, null, null, DefaultLanguage: null,
            AllowVersionOverwrite: null));    // explicit null → preserve
        Assert.True((await _repo.GetSettingsAsync(org.Id))!.AllowVersionOverwrite);
    }

    [Fact]
    public async Task UpsertLicensePolicyModeAsync_RoundTrip()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await _repo.UpsertLicensePolicyModeAsync(orgId, "warn");
        Assert.Equal("warn", (await _repo.GetSettingsAsync(orgId))!.LicenseEnforcementMode);
        await _repo.UpsertLicensePolicyModeAsync(orgId, "block");
        Assert.Equal("block", (await _repo.GetSettingsAsync(orgId))!.LicenseEnforcementMode);
    }

    [Fact]
    public async Task InstanceSettings_ListAsync_FiltersOutJwtSecret()
    {
        await _repo.SetInstanceSettingAsync("jwt_secret", "DO-NOT-LEAK");
        await _repo.SetInstanceSettingAsync("max_upload_bytes", "1048576");

        var listed = await _repo.ListInstanceSettingsAsync();
        Assert.False(listed.ContainsKey("jwt_secret"));
        Assert.Equal("1048576", listed["max_upload_bytes"]);

        // ScalarGet still returns it — used internally by JWT signing.
        Assert.Equal("DO-NOT-LEAK", await _repo.GetInstanceSettingAsync("jwt_secret"));
    }

    [Fact]
    public async Task SetInstanceSettingAsync_OnConflict_Overwrites()
    {
        await _repo.SetInstanceSettingAsync($"k-{Guid.NewGuid():N}", "v1");
        var key = (await _repo.ListInstanceSettingsAsync()).Keys.First(k => k.StartsWith("k-"));
        await _repo.SetInstanceSettingAsync(key, "v2");
        Assert.Equal("v2", await _repo.GetInstanceSettingAsync(key));
    }

    // ── User management projections ──────────────────────────────────────────

    [Fact]
    public async Task SetUserAccountStatusAsync_CaseInsensitive_AndRejectsUnknownStatus()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var slug = (await _repo.GetByIdAsync(orgId))!.Slug;
        var email = $"u-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        // Case-insensitive email lookup — the WHERE clause uses lower(u.email) = lower(@email).
        Assert.True(await _repo.SetUserAccountStatusAsync(email.ToUpperInvariant(), slug, "locked"));
        Assert.False(await _repo.SetUserAccountStatusAsync(email, slug, "tornado"));   // unknown status → reject
        Assert.False(await _repo.SetUserAccountStatusAsync("ghost@nowhere.test", slug, "locked"));   // unknown email
    }

    [Fact]
    public async Task LookupUsersAsync_NullFilters_ReturnsEmpty_NotEverything()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "noisy@x.test");
        var rows = await _repo.LookupUsersAsync(email: null, tenantSlug: null, limit: 10);
        Assert.Empty(rows);
    }

    [Fact]
    public async Task ListOrgMembersAsync_FiltersByTenant_AndOrdersByCreatedThenId()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgA, "u1@a.test");
        await UserSeeder.InsertAsync(_fixture.Store, orgA, "u2@a.test");
        await UserSeeder.InsertAsync(_fixture.Store, orgB, "outsider@b.test");

        var members = await _repo.ListOrgMembersAsync(orgA);
        Assert.Equal(2, members.Count);
        Assert.All(members, m => Assert.EndsWith("@a.test", m.Email));
    }

    [Fact]
    public async Task CountOwnersAsync_IgnoresOtherRoles()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "owner@x.test", role: "owner");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "admin@x.test", role: "admin");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "member@x.test", role: "member");
        Assert.Equal(1, await _repo.CountOwnersAsync(orgId));
    }

    [Fact]
    public async Task UpdateMemberRoleAsync_OnlyUpdatesUserInThatOrg()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        var aliceA = await UserSeeder.InsertAsync(_fixture.Store, orgA, "alice@a.test", role: "member");
        // Update for a user that exists but in a *different* org — must be a no-op.
        await _repo.UpdateMemberRoleAsync(orgB, aliceA, "admin");

        await using var conn = await _fixture.Store.OpenAsync();
        var role = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = aliceA });
        Assert.Equal("member", role);
    }
}
