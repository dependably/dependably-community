using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression for the <c>packages</c> rows that catalogue nothing. Proxy-cache eviction and the
/// retention version limit both remove a package's last version without GC'ing its parent row —
/// unlike the interactive delete paths, which call
/// <c>PackageRepository.DeletePackageIfEmptyAsync</c> — so the row lingers on the Packages page
/// reading as "0 versions" with nothing servable under it. The <c>delete_empty_package_rows</c>
/// one-shot reclaims the accumulated backlog.
///
/// Every deletion case is paired with a must-NOT twin, because a sweep keyed on "has no versions"
/// is one missing predicate away from deleting live packages: the emptiness test spans two planes
/// (<c>package_versions</c> AND the cache plane), and it spares both an in-flight publish's
/// not-yet-populated row and a row carrying deliberate per-package policy.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmptyPackageRowSweepMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private SchemaInitializer Init() => new(_db, time: _clock);

    // Applies the schema, seeds a package row at the given age, then re-arms the sweep so the
    // next InitializeAsync runs it against the seeded state.
    private async Task SeedPackageAsync(
        string packageId, TimeSpan age, string? pushOverride = null)
    {
        await Init().InitializeAsync();
        await using var setup = await _db.OpenAsync();

        await setup.ExecuteAsync(
            "INSERT OR IGNORE INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await setup.ExecuteAsync(
            """
            INSERT OR IGNORE INTO packages
                (id, org_id, ecosystem, name, purl_name, is_proxy, created_at, same_version_push_override)
            VALUES (@id, 'o1', 'npm', @name, @name, 1, @createdAt, @pushOverride)
            """,
            new
            {
                id = packageId,
                name = packageId,
                createdAt = _clock.GetUtcNow().Subtract(age).ToUtcIso(),
                pushOverride,
            });
    }

    private async Task ReArmAndRunAsync()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'delete_empty_package_rows'");
        }

        await Init().InitializeAsync();
    }

    private async Task<bool> PackageExistsAsync(string packageId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM packages WHERE id = @id", new { id = packageId }) > 0;
    }

    private async Task AddHostedVersionAsync(string packageId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin)
            VALUES (@id, @packageId, '1.0.0', @purl, 'hosted/x', 'uploaded')
            """,
            new { id = "v-" + packageId, packageId, purl = $"pkg:npm/{packageId}@1.0.0" });
    }

    private async Task AddCachePlaneVersionAsync(string purlName)
    {
        await using var conn = await _db.OpenAsync();
        string caId = "ca-" + purlName;
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
            VALUES (@caId, 'npm', @name, '1.0.0', @filename, 'proxy/deadbeef', 'deadbeef')
            """,
            new { caId, name = purlName, filename = $"{purlName}-1.0.0.tgz" });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', @caId)",
            new { caId });
    }

    [Fact]
    public async Task Migration_DeletesPackageEmptyOnBothPlanes()
    {
        await SeedPackageAsync("residue", age: TimeSpan.FromDays(60));

        await ReArmAndRunAsync();

        Assert.False(await PackageExistsAsync("residue"));
    }

    // Must-NOT twin: the hosted plane still catalogues a version.
    [Fact]
    public async Task Migration_KeepsPackageWithHostedVersion()
    {
        await SeedPackageAsync("hosted", age: TimeSpan.FromDays(60));
        await AddHostedVersionAsync("hosted");

        await ReArmAndRunAsync();

        Assert.True(await PackageExistsAsync("hosted"));
    }

    // Must-NOT twin, and the one a single-plane sweep gets wrong: a proxy-only package has no
    // package_versions row at all, so "no rows in package_versions" alone would delete a package
    // whose versions are still being served off the cache plane.
    [Fact]
    public async Task Migration_KeepsPackageWithCachePlaneVersionOnly()
    {
        await SeedPackageAsync("proxied", age: TimeSpan.FromDays(60));
        await AddCachePlaneVersionAsync("proxied");

        await ReArmAndRunAsync();

        Assert.True(await PackageExistsAsync("proxied"));
    }

    // Must-NOT twin for the age floor: a publish creates the packages row before its version row,
    // so a freshly-created empty row may be an in-flight publish on a concurrently-serving replica.
    [Fact]
    public async Task Migration_KeepsRecentlyCreatedEmptyPackage()
    {
        await SeedPackageAsync("in-flight", age: TimeSpan.FromMinutes(5));

        await ReArmAndRunAsync();

        Assert.True(await PackageExistsAsync("in-flight"));
    }

    // Must-NOT twin for the policy guard: same_version_push_override is deliberate operator
    // configuration that is not reconstructible from anything else.
    [Fact]
    public async Task Migration_KeepsEmptyPackageCarryingPushOverride()
    {
        await SeedPackageAsync("policied", age: TimeSpan.FromDays(60), pushOverride: "block");

        await ReArmAndRunAsync();

        Assert.True(await PackageExistsAsync("policied"));
    }
}
