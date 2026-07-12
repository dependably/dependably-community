using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Per-file record store for hosted PyPI versions. The download-resolution lookup is the
/// tenant-sensitive surface: filenames are only unique per org, so a lookup must never
/// resolve another org's file record even when the filenames collide exactly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageVersionFilesRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
    private PackageVersionFilesRepository _repo = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new PackageVersionFilesRepository(_db, _clock);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('p1', 'o1', 'pypi', 'demo', 'demo', 0),
                   ('p2', 'o2', 'pypi', 'demo', 'demo', 0)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, origin)
            VALUES ('v1', 'p1', '1.0.0', 'pkg:pypi/demo@1.0.0',
                    'hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl',
                    'demo-1.0.0-py3-none-any.whl', 10, 'uploaded'),
                   ('v2', 'p2', '1.0.0', 'pkg:pypi/demo@1.0.0',
                    'hosted/o2/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl',
                    'demo-1.0.0-py3-none-any.whl', 10, 'uploaded')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FindFileWithVersion_IsOrgScoped_IdenticalFilenamesNeverCross()
    {
        await _repo.AddAsync("v1", "o1", "demo-1.0.0-py3-none-any.whl",
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 10, "sha-o1");
        await _repo.AddAsync("v2", "o2", "demo-1.0.0-py3-none-any.whl",
            "hosted/o2/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 10, "sha-o2");

        var o1Hit = await _repo.FindFileWithVersionAsync("o1", "pypi", "demo-1.0.0-py3-none-any.whl");
        Assert.NotNull(o1Hit);
        Assert.Equal("sha-o1", o1Hit.Value.File.ChecksumSha256);
        Assert.StartsWith("hosted/o1/", o1Hit.Value.File.BlobKey);
        Assert.Equal("o1", o1Hit.Value.Package.OrgId);

        var o2Hit = await _repo.FindFileWithVersionAsync("o2", "pypi", "demo-1.0.0-py3-none-any.whl");
        Assert.NotNull(o2Hit);
        Assert.Equal("sha-o2", o2Hit.Value.File.ChecksumSha256);

        // A third org sees nothing.
        Assert.Null(await _repo.FindFileWithVersionAsync("o3", "pypi", "demo-1.0.0-py3-none-any.whl"));
        // Ecosystem is part of the key: the same filename under another ecosystem misses.
        Assert.Null(await _repo.FindFileWithVersionAsync("o1", "npm", "demo-1.0.0-py3-none-any.whl"));
    }

    [Fact]
    public async Task UpdateForOverwrite_RefreshesFileFacts_ParentSum_AndScanState()
    {
        var wheel = await _repo.AddAsync("v1", "o1", "demo-1.0.0-py3-none-any.whl",
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 100, "sha-a");
        await _repo.AddAsync("v1", "o1", "demo-1.0.0.tar.gz",
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 40, "sha-b");

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET vuln_checked_at = '2024-06-01T00:00:00Z' WHERE id = 'v1'");
        }

        await _repo.UpdateForOverwriteAsync(wheel.Id,
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 130, "sha-a2");

        var files = await _repo.GetByVersionAsync("v1");
        Assert.Equal(2, files.Count);
        Assert.Equal(130, files.Single(f => f.Filename.EndsWith(".whl")).SizeBytes);
        Assert.Equal("sha-a2", files.Single(f => f.Filename.EndsWith(".whl")).ChecksumSha256);

        await using (var conn = await _db.OpenAsync())
        {
            var (size, vulnCheckedAt) = await conn.QuerySingleAsync<(long, string?)>(
                "SELECT size_bytes, vuln_checked_at FROM package_versions WHERE id = 'v1'");
            // Parent size is the SUM of its files; scan state resets because bytes changed.
            Assert.Equal(170, size);
            Assert.Null(vulnCheckedAt);
        }
    }

    [Fact]
    public async Task GetBlobKeysForVersion_ReturnsEveryFileBlob()
    {
        await _repo.AddAsync("v1", "o1", "demo-1.0.0-py3-none-any.whl",
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", 100, "sha-a");
        await _repo.AddAsync("v1", "o1", "demo-1.0.0.tar.gz",
            "hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", 40, "sha-b");

        var keys = await _repo.GetBlobKeysForVersionAsync("v1");
        Assert.Equal(2, keys.Count);
        Assert.Contains("hosted/o1/pypi/demo/1.0.0/demo-1.0.0-py3-none-any.whl", keys);
        Assert.Contains("hosted/o1/pypi/demo/1.0.0/demo-1.0.0.tar.gz", keys);
    }
}
