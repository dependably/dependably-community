using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Round-trips the install-script signal through <see cref="PackageRepository"/>: the
/// <c>has_install_script</c> / <c>install_script_kind</c> columns must persist on
/// <see cref="PackageRepository.UpdateInstallScriptAsync"/> and re-hydrate on every
/// <see cref="PackageVersion"/> read path (a missed alias would silently default to false and
/// the block-gate arm would never fire).
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstallScriptPersistenceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private PackageRepository _packages = default!;
    private string _orgId = default!;
    private string _pkgId = default!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _packages = new PackageRepository(_db, time: _clock);

        await using var conn = await _db.OpenAsync();
        _orgId = $"org-{Guid.NewGuid():N}";
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = _orgId });

        _pkgId = $"pkg-{Guid.NewGuid():N}";
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@pkgId, @orgId, 'npm', 'lib', 'lib')",
            new { pkgId = _pkgId, orgId = _orgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task NewVersion_DefaultsToNoInstallScript()
    {
        var created = await CreateVersionAsync("1.0.0");

        Assert.False(created.HasInstallScript);
        Assert.Null(created.InstallScriptKind);
    }

    [Fact]
    public async Task UpdateInstallScript_PersistsAndHydratesAcrossReadPaths()
    {
        var created = await CreateVersionAsync("2.0.0");
        await _packages.UpdateInstallScriptAsync(created.Id, true, "npm:postinstall");

        // GetVersionByIdAsync (download / proxy serve path).
        var byId = await _packages.GetVersionByIdAsync(_orgId, created.Id);
        Assert.NotNull(byId);
        Assert.True(byId!.HasInstallScript);
        Assert.Equal("npm:postinstall", byId.InstallScriptKind);

        // GetVersionsAsync (block-gate listing / IsHardBlockedByStoredState feeder).
        var list = await _packages.GetVersionsAsync(_pkgId);
        var fromList = Assert.Single(list, v => v.Id == created.Id);
        Assert.True(fromList.HasInstallScript);
        Assert.Equal("npm:postinstall", fromList.InstallScriptKind);

        // GetVersionAsync (publish dedup / NuGet / Cargo path).
        var byVersion = await _packages.GetVersionAsync(_pkgId, "2.0.0");
        Assert.NotNull(byVersion);
        Assert.True(byVersion!.HasInstallScript);
        Assert.Equal("npm:postinstall", byVersion.InstallScriptKind);

        // GetVersionByBlobKeyAsync (PyPI/npm blob-key lookup path).
        var byBlob = await _packages.GetVersionByBlobKeyAsync(_orgId, byId.BlobKey);
        Assert.NotNull(byBlob);
        Assert.True(byBlob!.HasInstallScript);
        Assert.Equal("npm:postinstall", byBlob.InstallScriptKind);
    }

    [Fact]
    public async Task UpdateInstallScript_NegativeResult_ClearsKind()
    {
        var created = await CreateVersionAsync("3.0.0");
        await _packages.UpdateInstallScriptAsync(created.Id, true, "npm:install");

        // Re-detection now finds no script (e.g. a republished, cleaned artefact).
        await _packages.UpdateInstallScriptAsync(created.Id, false, null);

        var reread = await _packages.GetVersionByIdAsync(_orgId, created.Id);
        Assert.NotNull(reread);
        Assert.False(reread!.HasInstallScript);
        Assert.Null(reread.InstallScriptKind);
    }

    [Fact]
    public async Task UpdateInstallScript_FalseWithKind_DoesNotPersistKind()
    {
        // Defensive: a hasScript=false call must never leave a dangling kind.
        var created = await CreateVersionAsync("4.0.0");
        await _packages.UpdateInstallScriptAsync(created.Id, false, "npm:postinstall");

        var reread = await _packages.GetVersionByIdAsync(_orgId, created.Id);
        Assert.NotNull(reread);
        Assert.False(reread!.HasInstallScript);
        Assert.Null(reread.InstallScriptKind);
    }

    private async Task<PackageVersion> CreateVersionAsync(string version)
    {
        string purl = $"pkg:npm/{Guid.NewGuid():N}/lib@{version}";
        string blobKey = $"registry/npm/lib/{version}/lib-{version}.tgz";
        return await _packages.CreateVersionAsync(
            new NewPackageVersion(_pkgId, version, purl, blobKey, 1000, "aaaa", Origin: "hosted"));
    }
}
