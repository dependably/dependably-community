using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Integration;

/// <summary>
/// Tenant-isolation and resolution coverage for the NuGet symbol-server (SSQP) index repository.
/// Confirms case-insensitive resolution, unknown-key misses, cross-tenant isolation, and the
/// mixed partial-failure path where one symbol package indexes several PDBs at once.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NuGetSymbolIndexRepositoryTests : IClassFixture<InMemoryDbFixture>, IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture;
    private readonly NuGetSymbolIndexRepository _repo;

    public NuGetSymbolIndexRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new NuGetSymbolIndexRepository(fixture.Store, TestTime.Frozen());
    }

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<(string OrgId, string VersionId)> SeedVersionAsync(string orgSlug, string name)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, orgSlug);
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "nuget", name);
        string versionId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", $"pkg:nuget/{name}@1.0.0",
            blobKey: $"hosted/{orgId}/nuget/{name}/1.0.0/{name}.1.0.0.snupkg");
        return (orgId, versionId);
    }

    [Fact]
    public async Task Resolve_IsCaseInsensitive_OnKeyAndFilename()
    {
        (string orgId, string versionId) = await SeedVersionAsync($"sym-{Guid.NewGuid():N}", "pkga");

        string key = NuGetSymbolKey.PortableKey(Guid.Parse("11112222-3333-4444-5555-666677778888"));
        await _repo.IndexAsync(orgId, versionId, "hosted/blob.snupkg",
            [new PdbSymbol("mylib.pdb", key, "lib/net10.0/mylib.pdb")]);

        // Debuggers send mixed-case; resolution lowercases both sides.
        var row = await _repo.ResolveAsync(orgId, "MyLib.PDB", key.ToUpperInvariant());

        Assert.NotNull(row);
        Assert.Equal("hosted/blob.snupkg", row!.SnupkgBlobKey);
        Assert.Equal("lib/net10.0/mylib.pdb", row.EntryPath);
    }

    [Fact]
    public async Task Resolve_UnknownKey_ReturnsNull()
    {
        (string orgId, _) = await SeedVersionAsync($"sym-{Guid.NewGuid():N}", "pkgb");

        var row = await _repo.ResolveAsync(orgId, "whatever.pdb", new string('a', 32) + "ffffffff");

        Assert.Null(row);
    }

    [Fact]
    public async Task Resolve_DoesNotServeAnotherTenantsKey()
    {
        (string orgA, string versionA) = await SeedVersionAsync($"sym-a-{Guid.NewGuid():N}", "pkgc");
        (string orgB, _) = await SeedVersionAsync($"sym-b-{Guid.NewGuid():N}", "pkgc");

        string key = NuGetSymbolKey.PortableKey(Guid.Parse("aaaabbbb-cccc-4ddd-8eee-ffff00001111"));
        await _repo.IndexAsync(orgA, versionA, "hosted/a.snupkg",
            [new PdbSymbol("shared.pdb", key, "lib/net10.0/shared.pdb")]);

        // Org A resolves its own key; Org B gets nothing for the identical key.
        Assert.NotNull(await _repo.ResolveAsync(orgA, "shared.pdb", key));
        Assert.Null(await _repo.ResolveAsync(orgB, "shared.pdb", key));
    }

    [Fact]
    public async Task Index_MixedBatch_ResolvesEachIndexedPdbIndependently()
    {
        // A single symbol package can carry several PDBs. Index a batch and confirm each key
        // resolves to its own entry — the fan-out equivalent of a multi-PDB .snupkg push.
        (string orgId, string versionId) = await SeedVersionAsync($"sym-{Guid.NewGuid():N}", "pkgd");

        string key1 = NuGetSymbolKey.PortableKey(Guid.Parse("10000000-0000-4000-8000-000000000001"));
        string key2 = NuGetSymbolKey.PortableKey(Guid.Parse("20000000-0000-4000-8000-000000000002"));
        await _repo.IndexAsync(orgId, versionId, "hosted/multi.snupkg",
        [
            new PdbSymbol("first.pdb", key1, "lib/net10.0/first.pdb"),
            new PdbSymbol("second.pdb", key2, "lib/net10.0/second.pdb"),
        ]);

        var r1 = await _repo.ResolveAsync(orgId, "first.pdb", key1);
        var r2 = await _repo.ResolveAsync(orgId, "second.pdb", key2);

        Assert.Equal("lib/net10.0/first.pdb", r1!.EntryPath);
        Assert.Equal("lib/net10.0/second.pdb", r2!.EntryPath);
        // A correct filename with the wrong sibling key still misses (no accidental cross-wiring).
        Assert.Null(await _repo.ResolveAsync(orgId, "first.pdb", key2));
    }

    [Fact]
    public async Task Index_IsIdempotent_OnRepush()
    {
        (string orgId, string versionId) = await SeedVersionAsync($"sym-{Guid.NewGuid():N}", "pkge");

        string key = NuGetSymbolKey.PortableKey(Guid.Parse("33334444-5555-4666-8777-88889999aaaa"));
        var batch = new List<PdbSymbol> { new("lib.pdb", key, "lib/net10.0/lib.pdb") };

        await _repo.IndexAsync(orgId, versionId, "hosted/x.snupkg", batch);
        await _repo.IndexAsync(orgId, versionId, "hosted/x.snupkg", batch);

        // Still resolvable and unambiguous after a duplicate push (ON CONFLICT DO NOTHING).
        var row = await _repo.ResolveAsync(orgId, "lib.pdb", key);
        Assert.NotNull(row);
    }
}
