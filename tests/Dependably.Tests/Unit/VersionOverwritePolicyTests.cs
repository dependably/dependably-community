using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class VersionOverwritePolicyTests
{
    // ── Resolver matrix ──────────────────────────────────────────────────────

    [Theory]
    // org='block': always denied regardless of per-package override
    [InlineData("block", null, false)]
    [InlineData("block", "allow", false)]
    [InlineData("block", "block", false)]
    // org='exception': blocked by default; only 'allow' per-package grants it
    [InlineData("exception", null, false)]
    [InlineData("exception", "allow", true)]
    [InlineData("exception", "block", false)]
    // org='allow': allowed by default; only 'block' per-package denies it
    [InlineData("allow", null, true)]
    [InlineData("allow", "allow", true)]
    [InlineData("allow", "block", false)]
    public void ResolveOverwriteAllowed_Matrix(string orgPolicy, string? pkgOverride, bool expected)
    {
        bool actual = PackagePublishService.ResolveOverwriteAllowed(orgPolicy, pkgOverride);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ResolveOverwriteAllowed_NullOrgPolicy_TreatedAsBlock()
    {
        // Null org policy (column not yet set on old schema row) falls back to 'block'.
        Assert.False(PackagePublishService.ResolveOverwriteAllowed(null, "allow"));
        Assert.False(PackagePublishService.ResolveOverwriteAllowed(null, null));
    }

    // ── Migration: allow_version_overwrite = 1 → version_overwrite_policy = 'allow' ──

    [Fact]
    public async Task Migration_AllowVersionOverwriteTrue_SetsAllow()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        await using var conn = await db.OpenAsync();

        // Seed an org row with allow_version_overwrite = 1 (simulates a pre-existing org).
        string orgId = await OrgSeeder.InsertAsync(db, "migrate-test-" + Guid.NewGuid().ToString("N")[..8]);
        await conn.ExecuteAsync(
            "UPDATE org_settings SET allow_version_overwrite = 1 WHERE org_id = @orgId",
            new { orgId });

        // Remove the ledger entry so the migration runs again on the next initializer call,
        // simulating a restart after the column was added but before the data backfill ran.
        await conn.ExecuteAsync(
            "DELETE FROM _applied_migrations WHERE name = 'migrate_allow_version_overwrite_to_policy'");

        // Run a fresh initializer — the migration must now backfill the policy column.
        await new SchemaInitializer(db).InitializeAsync();

        string? policy = await conn.ExecuteScalarAsync<string?>(
            "SELECT version_overwrite_policy FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        Assert.Equal("allow", policy);
    }

    [Fact]
    public async Task Migration_AllowVersionOverwriteFalse_LeavesBlock()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "migrate-block-" + Guid.NewGuid().ToString("N")[..8]);

        // Re-run initializer — no change expected (already 'block' by default).
        await new SchemaInitializer(db).InitializeAsync();

        await using var conn = await db.OpenAsync();
        string? policy = await conn.ExecuteScalarAsync<string?>(
            "SELECT version_overwrite_policy FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        Assert.Equal("block", policy);
    }

    // ── Dual-write: upsert keeps legacy bool in sync ──────────────────────────

    [Fact]
    public async Task UpsertSettings_PolicyAllow_DualWritesLegacyBoolToOne()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "dw-allow-" + Guid.NewGuid().ToString("N")[..8]);
        var repo = new OrgSettingsRepository(db);

        await repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: null, MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null,
            MaxUploadBytesNuGet: null, InstanceMaxUploadBytes: null,
            DefaultLanguage: null,
            VersionOverwritePolicy: "allow"));

        await using var conn = await db.OpenAsync();
        int legacyBool = await conn.ExecuteScalarAsync<int>(
            "SELECT allow_version_overwrite FROM org_settings WHERE org_id = @orgId",
            new { orgId });
        string? policy = await conn.ExecuteScalarAsync<string?>(
            "SELECT version_overwrite_policy FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        Assert.Equal(1, legacyBool);
        Assert.Equal("allow", policy);
    }

    [Fact]
    public async Task UpsertSettings_PolicyBlock_DualWritesLegacyBoolToZero()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "dw-block-" + Guid.NewGuid().ToString("N")[..8]);
        var repo = new OrgSettingsRepository(db);

        // First set to allow, then block — tests the update arm.
        await repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: null, MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null,
            MaxUploadBytesNuGet: null, InstanceMaxUploadBytes: null,
            DefaultLanguage: null,
            VersionOverwritePolicy: "allow"));

        await repo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: null, MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null,
            MaxUploadBytesNuGet: null, InstanceMaxUploadBytes: null,
            DefaultLanguage: null,
            VersionOverwritePolicy: "block"));

        await using var conn = await db.OpenAsync();
        int legacyBool = await conn.ExecuteScalarAsync<int>(
            "SELECT allow_version_overwrite FROM org_settings WHERE org_id = @orgId",
            new { orgId });
        string? policy = await conn.ExecuteScalarAsync<string?>(
            "SELECT version_overwrite_policy FROM org_settings WHERE org_id = @orgId",
            new { orgId });

        Assert.Equal(0, legacyBool);
        Assert.Equal("block", policy);
    }

    // ── OrgRepository.GetSettingsAsync projects VersionOverwritePolicy ──────

    [Fact]
    public async Task GetSettingsAsync_ReadsVersionOverwritePolicy()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "get-policy-" + Guid.NewGuid().ToString("N")[..8]);
        var settingsRepo = new OrgSettingsRepository(db);

        await settingsRepo.UpsertSettingsAsync(new OrgSettingsUpdate(
            OrgId: orgId,
            AnonymousPull: false, AllowlistMode: false,
            MaxUploadBytes: null, MaxUploadBytesPyPi: null, MaxUploadBytesNpm: null,
            MaxUploadBytesNuGet: null, InstanceMaxUploadBytes: null,
            DefaultLanguage: null,
            VersionOverwritePolicy: "exception"));

        var orgRepo = new OrgRepository(db);
        var settings = await orgRepo.GetSettingsAsync(orgId);

        Assert.NotNull(settings);
        Assert.Equal("exception", settings!.VersionOverwritePolicy);
    }

    // ── PackageRepository.SetSameVersionPushOverrideAsync ────────────────────

    [Fact]
    public async Task SetSameVersionPushOverrideAsync_PersistsAndReadsBack()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "pkg-override-" + Guid.NewGuid().ToString("N")[..8]);
        var pkgRepo = new PackageRepository(db);

        var pkg = await pkgRepo.GetOrCreateAsync(orgId, "npm", "mylib", "mylib", isProxy: false);
        Assert.Null(pkg.SameVersionPushOverride);

        await pkgRepo.SetSameVersionPushOverrideAsync(pkg.Id, orgId, "allow");
        var pkgAfter = await pkgRepo.GetByPurlNameAsync(orgId, "npm", "mylib");
        Assert.Equal("allow", pkgAfter?.SameVersionPushOverride);

        // Clear it
        await pkgRepo.SetSameVersionPushOverrideAsync(pkg.Id, orgId, null);
        var pkgCleared = await pkgRepo.GetByPurlNameAsync(orgId, "npm", "mylib");
        Assert.Null(pkgCleared?.SameVersionPushOverride);
    }

    // ── Cross-org BOLA guard: SetSameVersionPushOverrideAsync ignores wrong orgId ──

    [Fact]
    public async Task SetSameVersionPushOverrideAsync_WrongOrgId_NoUpdate()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(db, "bola-org-" + Guid.NewGuid().ToString("N")[..8]);
        string otherOrgId = await OrgSeeder.InsertAsync(db, "bola-other-" + Guid.NewGuid().ToString("N")[..8]);
        var pkgRepo = new PackageRepository(db);

        var pkg = await pkgRepo.GetOrCreateAsync(orgId, "npm", "private-lib", "private-lib", isProxy: false);

        // Attempt to set override using a different org's id — must be a no-op.
        await pkgRepo.SetSameVersionPushOverrideAsync(pkg.Id, otherOrgId, "allow");

        var pkgAfter = await pkgRepo.GetByPurlNameAsync(orgId, "npm", "private-lib");
        Assert.Null(pkgAfter?.SameVersionPushOverride);
    }

    // ── Mixed partial-failure scenario: some packages have overrides, some don't ──

    [Fact]
    public async Task PublishService_MixedOverrides_OnlyGrantedPackageAllowsOverwrite()
    {
        await using var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();

        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-mixed', 'mixed')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id, version_overwrite_policy) VALUES ('o-mixed', 'exception')");

        var pkgRepo = new PackageRepository(db);

        // Package A: no per-package override (inherits 'exception' = blocked by default)
        var pkgA = await pkgRepo.GetOrCreateAsync("o-mixed", "npm", "lib-a", "lib-a", isProxy: false);
        // Package B: explicit 'allow' override
        var pkgB = await pkgRepo.GetOrCreateAsync("o-mixed", "npm", "lib-b", "lib-b", isProxy: false);
        await pkgRepo.SetSameVersionPushOverrideAsync(pkgB.Id, "o-mixed", "allow");

        // Refresh from DB so SameVersionPushOverride is populated.
        var pkgAFresh = await pkgRepo.GetByPurlNameAsync("o-mixed", "npm", "lib-a");
        var pkgBFresh = await pkgRepo.GetByPurlNameAsync("o-mixed", "npm", "lib-b");

        // Exception + no override → blocked
        Assert.False(PackagePublishService.ResolveOverwriteAllowed("exception", pkgAFresh?.SameVersionPushOverride));
        // Exception + allow → granted
        Assert.True(PackagePublishService.ResolveOverwriteAllowed("exception", pkgBFresh?.SameVersionPushOverride));
    }
}
