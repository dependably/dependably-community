using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Round-trips the provenance signal through <see cref="PackageRepository"/>: the
/// <c>provenance_status</c> / <c>provenance_signer</c> columns must persist on
/// <see cref="PackageRepository.UpdateProvenanceAsync"/> and re-hydrate on every
/// <see cref="PackageVersion"/> read path (a missed alias would silently default to NULL and the
/// provenance block-gate arm would never fire).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProvenancePersistenceTests : IAsyncLifetime
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
    public async Task NewVersion_DefaultsToNullProvenance()
    {
        var created = await CreateVersionAsync("1.0.0");

        Assert.Null(created.ProvenanceStatus);
        Assert.Null(created.ProvenanceSigner);
    }

    [Fact]
    public async Task UpdateProvenance_PersistsAndHydratesAcrossReadPaths()
    {
        var created = await CreateVersionAsync("2.0.0");
        await _packages.UpdateProvenanceAsync(created.Id, "verified", "SHA256:test-anchor");

        // GetVersionByIdAsync (download / proxy serve path).
        var byId = await _packages.GetVersionByIdAsync(_orgId, created.Id);
        Assert.NotNull(byId);
        Assert.Equal("verified", byId!.ProvenanceStatus);
        Assert.Equal("SHA256:test-anchor", byId.ProvenanceSigner);

        // GetVersionsAsync (block-gate listing / IsHardBlockedByStoredState feeder).
        var list = await _packages.GetVersionsAsync(_pkgId);
        var fromList = Assert.Single(list, v => v.Id == created.Id);
        Assert.Equal("verified", fromList.ProvenanceStatus);
        Assert.Equal("SHA256:test-anchor", fromList.ProvenanceSigner);

        // GetVersionAsync (publish dedup / NuGet / Cargo path).
        var byVersion = await _packages.GetVersionAsync(_pkgId, "2.0.0");
        Assert.NotNull(byVersion);
        Assert.Equal("verified", byVersion!.ProvenanceStatus);
        Assert.Equal("SHA256:test-anchor", byVersion.ProvenanceSigner);

        // GetVersionByBlobKeyAsync (PyPI/npm blob-key lookup path).
        var byBlob = await _packages.GetVersionByBlobKeyAsync(_orgId, byId.BlobKey);
        Assert.NotNull(byBlob);
        Assert.Equal("verified", byBlob!.ProvenanceStatus);
        Assert.Equal("SHA256:test-anchor", byBlob.ProvenanceSigner);
    }

    [Fact]
    public async Task UpdateProvenance_FailedAndUnsigned_PersistWithNullSigner()
    {
        var failed = await CreateVersionAsync("3.0.0");
        await _packages.UpdateProvenanceAsync(failed.Id, "failed", null);
        var rereadFailed = await _packages.GetVersionByIdAsync(_orgId, failed.Id);
        Assert.Equal("failed", rereadFailed!.ProvenanceStatus);
        Assert.Null(rereadFailed.ProvenanceSigner);

        var unsigned = await CreateVersionAsync("4.0.0");
        await _packages.UpdateProvenanceAsync(unsigned.Id, "unsigned", null);
        var rereadUnsigned = await _packages.GetVersionByIdAsync(_orgId, unsigned.Id);
        Assert.Equal("unsigned", rereadUnsigned!.ProvenanceStatus);
        Assert.Null(rereadUnsigned.ProvenanceSigner);
    }

    private async Task<PackageVersion> CreateVersionAsync(string version)
    {
        string purl = $"pkg:npm/{Guid.NewGuid():N}/lib@{version}";
        string blobKey = $"registry/npm/lib/{version}/lib-{version}.tgz";
        return await _packages.CreateVersionAsync(
            new NewPackageVersion(_pkgId, version, purl, blobKey, 1000, "aaaa", Origin: "proxy"));
    }
}
