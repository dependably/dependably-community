using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The npm manifest rescan's retry bookkeeping against a live Postgres server. The retry keys live in
/// <c>instance_settings</c> and are found by prefix; a byte-order range scan over them matches
/// nothing under a locale-aware collation, so retries never ran and the marker was written with
/// failures outstanding. SQLite compares bytes and cannot show it.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class NpmManifestRescanPostgresTests
{
    private const string Clean = """{"name":"p","version":"1.0.0","license":"MIT"}""";
    private const string Evil = """{"name":"p","version":"1.0.0","scripts":{"postinstall":"x"}}""";

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException("TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    private static async Task<string> SeedAsync(IMetadataStore store, InMemoryBlobStore blobs, string name, string key, byte[] bytes)
    {
        await blobs.PutAsync(key, new MemoryStream(bytes));
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
            VALUES (@id, 'npm', @name, '1.0.0', @name || '-1.0.0.tgz', @key, 'h')
            """, new { id, name, key });
        return id;
    }

    private static async Task<string?> SettingAsync(IMetadataStore store, string key)
    {
        await using var conn = await store.OpenAsync();
        return await conn.QuerySingleOrDefaultAsync<string>("SELECT value FROM instance_settings WHERE key = @key", new { key });
    }

    private static async Task<(int Script, string? Kind)> FlagsAsync(IMetadataStore store, string id)
    {
        await using var conn = await store.OpenAsync();
        return await conn.QuerySingleAsync<(int, string?)>(
            "SELECT has_install_script, install_script_kind FROM cache_artifact WHERE id = @id", new { id });
    }

    private static NpmManifestRescan Build(IMetadataStore store, IBlobStore blobs) =>
        new(store, new TieredBlobStorage(blobs, blobs), TimeProvider.System, NullLogger<NpmManifestRescan>.Instance);

    [Fact]
    public async Task Failed_read_is_retried_on_a_later_tick_and_the_marker_waits_for_it()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        var memory = new InMemoryBlobStore();
        var blobs = new MidStreamFaultBlobStore(memory);
        string key = "proxy/" + new string('a', 64);
        string id = await SeedAsync(pg.Store, memory, "flaky", key, NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        await SeedAsync(pg.Store, memory, "zz-healthy", "proxy/" + new string('b', 64), NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        blobs.FailingKeys.Add(key);

        await Build(pg.Store, blobs).RunOnceAsync();
        Assert.Equal("1", await SettingAsync(pg.Store, NpmManifestRescan.FailKeyPrefix + "cache:" + id));
        Assert.Null(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));

        blobs.FailingKeys.Clear();
        await Build(pg.Store, blobs).RunOnceAsync();

        Assert.Null(await SettingAsync(pg.Store, NpmManifestRescan.FailKeyPrefix + "cache:" + id));
        Assert.NotNull(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));
        Assert.Equal((0, (string?)null), await FlagsAsync(pg.Store, id));
    }

    [Fact]
    public async Task Persistent_failure_is_flagged_unscannable_after_the_attempt_limit_and_keys_are_cleared()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        var memory = new InMemoryBlobStore();
        var blobs = new MidStreamFaultBlobStore(memory);
        string key = "proxy/" + new string('a', 64);
        string id = await SeedAsync(pg.Store, memory, "stuck", key, NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        await SeedAsync(pg.Store, memory, "zz-healthy", "proxy/" + new string('b', 64), NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        blobs.FailingKeys.Add(key);

        for (int run = 1; run < NpmManifestRescan.MaxAttempts; run++)
        {
            await Build(pg.Store, blobs).RunOnceAsync();
            Assert.Null(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));
        }

        await Build(pg.Store, blobs).RunOnceAsync();

        Assert.NotNull(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));
        Assert.Equal((1, (string?)NpmManifestRescan.UnscannableKind), await FlagsAsync(pg.Store, id));
        Assert.Null(await SettingAsync(pg.Store, NpmManifestRescan.FailKeyPrefix + "cache:" + id));
    }

    [Fact]
    public async Task Per_tick_cap_resumes_from_the_persisted_cursor()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        var memory = new InMemoryBlobStore();
        byte[] ambiguous = NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil));
        var ids = new List<string>();
        for (int i = 0; i < 5; i++)
        {
            ids.Add(await SeedAsync(pg.Store, memory, $"p{i}", "proxy/" + i.ToString("x").PadLeft(64, 'e'), ambiguous));
        }

        Assert.Equal(2, await Build(pg.Store, memory).RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.Equal(2, await Build(pg.Store, memory).RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.Null(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));
        Assert.Equal(1, await Build(pg.Store, memory).RunOnceAsync(batchRows: 2, maxBlobs: 2));
        Assert.NotNull(await SettingAsync(pg.Store, NpmManifestRescan.MarkerKey));
        foreach (string id in ids)
        {
            Assert.Equal(1, (await FlagsAsync(pg.Store, id)).Script);
        }
    }
}
