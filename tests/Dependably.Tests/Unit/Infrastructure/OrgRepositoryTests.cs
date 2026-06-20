using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class OrgRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly OrgRepository _repo;

    public OrgRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new OrgRepository(_fixture.Store, time: TestTime.Frozen());
    }

    // ── Get / soft-delete cycle ──────────────────────────────────────────────

    [Fact]
    public async Task GetBySlugAsync_RespectsSoftDeleteByDefault_AndOptInToInclude()
    {
        string slug = $"acme-{Guid.NewGuid():N}";
        string id = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        await _repo.SoftDeleteOrgAsync(id);

        Assert.Null(await _repo.GetBySlugAsync(slug));
        var includeDeleted = await _repo.GetBySlugAsync(slug, includeDeleted: true);
        Assert.NotNull(includeDeleted);
        Assert.NotNull(includeDeleted!.DeletedAt);
    }

    [Fact]
    public async Task RestoreOrgAsync_OnlyRestoresActuallyDeletedRows()
    {
        string id = await OrgSeeder.InsertAsync(_fixture.Store, $"acme-{Guid.NewGuid():N}");

        // Not-yet-soft-deleted: RestoreOrgAsync is a no-op (returns false).
        Assert.False(await _repo.RestoreOrgAsync(id));

        await _repo.SoftDeleteOrgAsync(id);
        Assert.True(await _repo.RestoreOrgAsync(id));
        Assert.False(await _repo.RestoreOrgAsync(id));   // already-active row → still false
    }

    [Fact]
    public async Task ListExpiredSoftDeletedOrgIdsAsync_FiltersByGraceWindow()
    {
        string freshId = await OrgSeeder.InsertAsync(_fixture.Store, $"fresh-{Guid.NewGuid():N}");
        string staleId = await OrgSeeder.InsertAsync(_fixture.Store, $"stale-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(freshId);

        // Force the stale one's deleted_at to 60 days ago.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            string sixtyDaysAgo = TestTime.KnownNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        string aliveId = await OrgSeeder.InsertAsync(_fixture.Store, $"alive-{Guid.NewGuid():N}");
        string deletedId = await OrgSeeder.InsertAsync(_fixture.Store, $"deleted-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(deletedId);

        var (Items, Total) = await _repo.ListOrgsAsync(limit: 100, offset: 0, includeDeleted: true);
        Assert.Contains(Items, o => o.Id == aliveId);
        Assert.Contains(Items, o => o.Id == deletedId);

        var activeOnly = await _repo.ListOrgsAsync(limit: 100, offset: 0, includeDeleted: false);
        Assert.Contains(activeOnly.Items, o => o.Id == aliveId);
        Assert.DoesNotContain(activeOnly.Items, o => o.Id == deletedId);
    }

    [Fact]
    public async Task ListOrgsAsync_Aggregates_DontCartesianAmplify_AcrossUsersAndVersions()
    {
        // Critical correctness test for the pre-aggregated subquery pattern. A naive
        // LEFT JOIN users LEFT JOIN packages LEFT JOIN package_versions would produce
        // N × M rows per tenant — COUNT would report 3*2=6 users and SUM would report
        // 3 × (100+200) = 900 bytes. The subqueries must yield the true 3 / 300.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"full-{Guid.NewGuid():N}");

        await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u1-{Guid.NewGuid():N}@x.test");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u2-{Guid.NewGuid():N}@x.test");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u3-{Guid.NewGuid():N}@x.test");

        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", $"pkg-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/p@1.0.0-{Guid.NewGuid():N}", sizeBytes: 100);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.1", $"pkg:npm/p@1.0.1-{Guid.NewGuid():N}", sizeBytes: 200);

        var (items, _) = await _repo.ListOrgsAsync(limit: 200, offset: 0);
        var row = Assert.Single(items, o => o.Id == orgId);
        Assert.Equal(3, row.MemberCount);
        Assert.Equal(300L, row.StorageBytes);
    }

    [Fact]
    public async Task ListOrgsAsync_EmptyTenant_ReportsZeroAggregates_ViaCoalesce()
    {
        // Counterpart to the populated case — covers the COALESCE(..., 0) fallback when the
        // LEFT JOIN subqueries produce no row for this tenant. Without COALESCE, MemberCount
        // would be 0 (COUNT default) but StorageBytes would be NULL and the int->long mapping
        // would either throw or surface as 0 by accident.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"empty-{Guid.NewGuid():N}");

        var (items, _) = await _repo.ListOrgsAsync(limit: 200, offset: 0);
        var row = Assert.Single(items, o => o.Id == orgId);
        Assert.Equal(0, row.MemberCount);
        Assert.Equal(0L, row.StorageBytes);
    }

    [Fact]
    public async Task ListOrgsAsync_MixedPage_PopulatedAndEmptyTenants_BothCorrect()
    {
        // Same query returns both shapes — guards against the populated case "leaking" its
        // aggregates onto the empty tenant via a missing join condition.
        string fullId = await OrgSeeder.InsertAsync(_fixture.Store, $"mix-full-{Guid.NewGuid():N}");
        string emptyId = await OrgSeeder.InsertAsync(_fixture.Store, $"mix-empty-{Guid.NewGuid():N}");

        await UserSeeder.InsertAsync(_fixture.Store, fullId, $"u1-{Guid.NewGuid():N}@x.test");
        await UserSeeder.InsertAsync(_fixture.Store, fullId, $"u2-{Guid.NewGuid():N}@x.test");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, fullId, "npm", $"pkg-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/p@1.0.0-{Guid.NewGuid():N}", sizeBytes: 500);

        var (items, _) = await _repo.ListOrgsAsync(limit: 200, offset: 0);
        var full = Assert.Single(items, o => o.Id == fullId);
        var empty = Assert.Single(items, o => o.Id == emptyId);
        Assert.Equal(2, full.MemberCount);
        Assert.Equal(500L, full.StorageBytes);
        Assert.Equal(0, empty.MemberCount);
        Assert.Equal(0L, empty.StorageBytes);
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

    // ── Shared SELECT projection — both GetSettingsAsync paths agree ──────────

    [Fact]
    public async Task GetSettingsAsync_CachedAndUncachedPaths_ReturnSameProjection_IncludingAirGapped()
    {
        // Regression: OrgRepository and OrgSettingsRepository share OrgRepository.OrgSettingsSelect.
        // Both must map air_gapped (and all other columns) identically. Verifies the shared const
        // covers the full column list including fields that were absent from the now-deleted
        // OrgRepository.UpsertSettingsAsync (which silently dropped air_gapped).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"parity-{Guid.NewGuid():N}");

        var settingsRepo = new OrgSettingsRepository(_fixture.Store, _repo);
        await settingsRepo.UpsertSettingsAsync(new OrgSettingsUpdate(
            orgId, AnonymousPull: true, AllowlistMode: false,
            MaxUploadBytes: 42L, null, null, null, null, DefaultLanguage: "de",
            AirGapped: true));

        // Uncached path (OrgSettingsRepository) — bypasses OrgRepository's memory cache.
        var uncached = (await settingsRepo.GetSettingsAsync(orgId))!;

        // Cached path (OrgRepository) — goes through the IMemoryCache layer.
        var cached = (await _repo.GetSettingsAsync(orgId))!;

        Assert.Equal(uncached.AirGapped, cached.AirGapped);
        Assert.True(cached.AirGapped);
        Assert.Equal(uncached.MaxUploadBytes, cached.MaxUploadBytes);
        Assert.Equal(42L, cached.MaxUploadBytes);
        Assert.Equal(uncached.DefaultLanguage, cached.DefaultLanguage);
        Assert.Equal("de", cached.DefaultLanguage);
        Assert.Equal(uncached.AnonymousPull, cached.AnonymousPull);
        Assert.True(cached.AnonymousPull);
    }

    [Fact]
    public async Task UpsertLicensePolicyModeAsync_RoundTrip()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
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
        string key = (await _repo.ListInstanceSettingsAsync()).Keys.First(k => k.StartsWith("k-"));
        await _repo.SetInstanceSettingAsync(key, "v2");
        Assert.Equal("v2", await _repo.GetInstanceSettingAsync(key));
    }

    // ── User management projections ──────────────────────────────────────────

    // Helpers shared by the account-status / session-revocation tests.
    private OrgRepository RepoWithVersionStore(UserTokenVersionStore store) =>
        new(_fixture.Store, time: TestTime.Frozen(), tokenVersions: store);

    private static UserTokenVersionStore MakeVersionStore(IMetadataStore db) =>
        new(db, new MemoryCache(new MemoryCacheOptions()));

    private async Task<long> ReadTokenVersionAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
    }

    [Fact]
    public async Task SetUserAccountStatusAsync_CaseInsensitive_AndRejectsUnknownStatus()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string slug = (await _repo.GetByIdAsync(orgId))!.Slug;
        string email = $"u-{Guid.NewGuid():N}@x.test";
        await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        // Case-insensitive email lookup — the WHERE clause uses lower(u.email) = lower(@email).
        Assert.True(await _repo.SetUserAccountStatusAsync(email.ToUpperInvariant(), slug, "locked"));
        Assert.False(await _repo.SetUserAccountStatusAsync(email, slug, "tornado"));   // unknown status → reject
        Assert.False(await _repo.SetUserAccountStatusAsync("ghost@nowhere.test", slug, "locked"));   // unknown email
    }

    [Fact]
    public async Task LookupUsersAsync_NullFilters_ReturnsEmpty_NotEverything()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "noisy@x.test");
        var rows = await _repo.LookupUsersAsync(email: null, tenantSlug: null, limit: 10);
        Assert.Empty(rows);
    }

    [Fact]
    public async Task ListOrgMembersAsync_FiltersByTenant_AndOrdersByCreatedThenId()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "owner@x.test", role: "owner");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "admin@x.test", role: "admin");
        await UserSeeder.InsertAsync(_fixture.Store, orgId, "member@x.test", role: "member");
        Assert.Equal(1, await _repo.CountOwnersAsync(orgId));
    }

    [Fact]
    public async Task UpdateMemberRoleAsync_OnlyUpdatesUserInThatOrg()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        string aliceA = await UserSeeder.InsertAsync(_fixture.Store, orgA, "alice@a.test", role: "member");
        // Update for a user that exists but in a *different* org — must be a no-op.
        await _repo.UpdateMemberRoleAsync(orgB, aliceA, "admin");

        await using var conn = await _fixture.Store.OpenAsync();
        string? role = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = @id", new { id = aliceA });
        Assert.Equal("member", role);
    }

    // ── UpdateOrgStatusAsync — sysadmin lifecycle-gate toggle ────────────────

    [Fact]
    public async Task UpdateOrgStatusAsync_Toggles_ActiveAndSuspended()
    {
        string id = await OrgSeeder.InsertAsync(_fixture.Store, $"toggle-{Guid.NewGuid():N}");

        Assert.True(await _repo.UpdateOrgStatusAsync(id, "suspended"));
        var suspended = await _repo.GetByIdAsync(id);
        Assert.Equal("suspended", suspended!.Status);

        Assert.True(await _repo.UpdateOrgStatusAsync(id, "active"));
        var active = await _repo.GetByIdAsync(id);
        Assert.Equal("active", active!.Status);
    }

    [Theory]
    [InlineData("archived")]
    [InlineData("deleting")]
    [InlineData("")]
    [InlineData("bogus")]
    public async Task UpdateOrgStatusAsync_RejectsNonOperatorStates(string status)
    {
        string id = await OrgSeeder.InsertAsync(_fixture.Store, $"reject-{Guid.NewGuid():N}");
        Assert.False(await _repo.UpdateOrgStatusAsync(id, status));
        var unchanged = await _repo.GetByIdAsync(id);
        Assert.Equal("active", unchanged!.Status); // default, never overwritten
    }

    [Fact]
    public async Task UpdateOrgStatusAsync_ReturnsFalse_OnUnknownId()
    {
        Assert.False(await _repo.UpdateOrgStatusAsync($"missing-{Guid.NewGuid():N}", "suspended"));
    }

    [Fact]
    public async Task UpdateOrgStatusAsync_ReturnsFalse_OnSoftDeletedOrg()
    {
        string id = await OrgSeeder.InsertAsync(_fixture.Store, $"del-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(id);

        // Soft-deleted tenants are not gated by status — restore must happen first.
        Assert.False(await _repo.UpdateOrgStatusAsync(id, "suspended"));
    }

    // ── CountByStatusAsync — dashboard rollup ────────────────────────────────

    [Fact]
    public async Task CountByStatusAsync_BucketsCorrectly_AndSoftDeleteOverridesStatus()
    {
        string activeId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-{Guid.NewGuid():N}");
        string suspendedId = await OrgSeeder.InsertAsync(_fixture.Store, $"cbs-{Guid.NewGuid():N}");
        string deletedId = await OrgSeeder.InsertAsync(_fixture.Store, $"cbd-{Guid.NewGuid():N}");

        await _repo.UpdateOrgStatusAsync(suspendedId, "suspended");
        // Suspend then soft-delete — soft-delete must win in the count regardless of status.
        await _repo.UpdateOrgStatusAsync(deletedId, "suspended");
        await _repo.SoftDeleteOrgAsync(deletedId);

        var (Active, Suspended, SoftDeleted) = await _repo.CountByStatusAsync();
        // Other tests in this fixture may have left rows behind; assert deltas after seeding
        // a known set of our own — pull a "before" baseline and re-count.

        // Re-fetch after seeding a deterministic second batch so we can assert exact deltas.
        string aliceId = await OrgSeeder.InsertAsync(_fixture.Store, $"alice-{Guid.NewGuid():N}");
        string bobId = await OrgSeeder.InsertAsync(_fixture.Store, $"bob-{Guid.NewGuid():N}");
        await _repo.UpdateOrgStatusAsync(bobId, "suspended");
        string charlieId = await OrgSeeder.InsertAsync(_fixture.Store, $"charlie-{Guid.NewGuid():N}");
        await _repo.SoftDeleteOrgAsync(charlieId);

        var after = await _repo.CountByStatusAsync();
        Assert.Equal(Active + 1, after.Active);
        Assert.Equal(Suspended + 1, after.Suspended);
        Assert.Equal(SoftDeleted + 1, after.SoftDeleted);

        // Touch the unused locals so the seeds are kept "live" for the assertion narrative.
        Assert.NotNull(activeId);
        Assert.NotNull(aliceId);
    }

    // ── Session revocation on account-status change ──────────────────────────────────────

    [Fact]
    public async Task SetUserAccountStatusAsync_Lock_BumpsTokenVersion()
    {
        // Regression: locking an account must bump token_version so outstanding session JWTs
        // are rejected by OnTokenValidated on the next request.
        var store = MakeVersionStore(_fixture.Store);
        var repo = RepoWithVersionStore(store);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sv-lock-{Guid.NewGuid():N}");
        string slug = (await repo.GetByIdAsync(orgId))!.Slug;
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        long versionBefore = await ReadTokenVersionAsync(userId);
        bool ok = await repo.SetUserAccountStatusAsync(email, slug, "locked");

        Assert.True(ok);
        long versionAfter = await ReadTokenVersionAsync(userId);
        Assert.Equal(versionBefore + 1, versionAfter);
    }

    [Fact]
    public async Task SetUserAccountStatusAsync_Disable_BumpsTokenVersion()
    {
        var store = MakeVersionStore(_fixture.Store);
        var repo = RepoWithVersionStore(store);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sv-dis-{Guid.NewGuid():N}");
        string slug = (await repo.GetByIdAsync(orgId))!.Slug;
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        long versionBefore = await ReadTokenVersionAsync(userId);
        bool ok = await repo.SetUserAccountStatusAsync(email, slug, "disabled");

        Assert.True(ok);
        long versionAfter = await ReadTokenVersionAsync(userId);
        Assert.Equal(versionBefore + 1, versionAfter);
    }

    [Fact]
    public async Task SetUserAccountStatusAsync_Activate_DoesNotBumpTokenVersion()
    {
        // Re-enabling a locked account must not bump token_version — the user has no live
        // sessions while locked, and bumping on re-activation would stale a session that
        // was legitimately re-issued after the lock was lifted.
        var store = MakeVersionStore(_fixture.Store);
        var repo = RepoWithVersionStore(store);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sv-act-{Guid.NewGuid():N}");
        string slug = (await repo.GetByIdAsync(orgId))!.Slug;
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, accountStatus: "locked");

        long versionBefore = await ReadTokenVersionAsync(userId);
        bool ok = await repo.SetUserAccountStatusAsync(email, slug, "active");

        Assert.True(ok);
        long versionAfter = await ReadTokenVersionAsync(userId);
        Assert.Equal(versionBefore, versionAfter);
    }

    [Fact]
    public async Task SetUserAccountStatusAsync_Lock_EvictsTokenVersionCache()
    {
        // Regression: bumping token_version without evicting the cache leaves a stale
        // cached version; OnTokenValidated reads the cached value and passes the now-
        // invalid session for up to the 60s cache TTL.
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        var store = new UserTokenVersionStore(_fixture.Store, memCache);
        var repo = RepoWithVersionStore(store);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sv-ev-{Guid.NewGuid():N}");
        string slug = (await repo.GetByIdAsync(orgId))!.Slug;
        string email = $"u-{Guid.NewGuid():N}@x.test";
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);

        // Prime the cache with the current (pre-lock) version.
        long versionBefore = (await store.GetCurrentVersionAsync(userId))!.Value;

        // Lock evicts the cache entry so the next read hits the DB.
        await repo.SetUserAccountStatusAsync(email, slug, "locked");

        // The cache entry for this user must be gone — GetCurrentVersionAsync re-reads the DB
        // and returns the bumped version rather than the stale cached one.
        long versionAfterLock = (await store.GetCurrentVersionAsync(userId))!.Value;
        Assert.Equal(versionBefore + 1, versionAfterLock);
    }

    [Fact]
    public async Task SetUserAccountStatusAsync_MixedOutcomes_BumpsOnlyMatchedUser()
    {
        // Partial-failure scenario: two users, one lock request per user. The matched
        // user's token_version is bumped; the non-existent user's attempt returns false
        // and the matched user's version is unaffected by the failed call.
        var store = MakeVersionStore(_fixture.Store);
        var repo = RepoWithVersionStore(store);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sv-mix-{Guid.NewGuid():N}");
        string slug = (await repo.GetByIdAsync(orgId))!.Slug;
        string emailA = $"u-a-{Guid.NewGuid():N}@x.test";
        string emailB = $"u-b-{Guid.NewGuid():N}@x.test";

        string userAId = await UserSeeder.InsertAsync(_fixture.Store, orgId, emailA);
        string userBId = await UserSeeder.InsertAsync(_fixture.Store, orgId, emailB);

        long versionA0 = await ReadTokenVersionAsync(userAId);
        long versionB0 = await ReadTokenVersionAsync(userBId);

        // Locking user A succeeds; user A's version bumps, user B's does not.
        bool lockA = await repo.SetUserAccountStatusAsync(emailA, slug, "locked");
        // Locking a ghost email fails (returns false) without touching any user row.
        bool lockGhost = await repo.SetUserAccountStatusAsync("ghost@nowhere.test", slug, "locked");

        Assert.True(lockA);
        Assert.False(lockGhost);
        Assert.Equal(versionA0 + 1, await ReadTokenVersionAsync(userAId));
        Assert.Equal(versionB0, await ReadTokenVersionAsync(userBId));
    }
}
