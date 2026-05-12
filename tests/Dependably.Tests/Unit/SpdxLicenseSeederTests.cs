using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SpdxLicenseSeederTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() =>
        await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task SchemaInit_SeedsSpdxLicenseTable()
    {
        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM spdx_license");
        // SPDX 3.28.0 ships 727 licenses; assert "a lot" without pinning to an exact number.
        Assert.True(count > 500, $"expected >500 SPDX rows after seed, got {count}");
    }

    [Fact]
    public async Task SchemaInit_StoresVersionInInstanceSettings()
    {
        await using var conn = await _db.OpenAsync();
        var version = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'spdx_list_version'");
        Assert.Equal("3.28.0", version);
    }

    [Fact]
    public async Task SchemaInit_AppliesCopyleftOverlay()
    {
        await using var conn = await _db.OpenAsync();
        var mit = await conn.ExecuteScalarAsync<string>(
            "SELECT copyleft FROM spdx_license WHERE identifier = 'MIT'");
        Assert.Equal("permissive", mit);

        var gpl = await conn.ExecuteScalarAsync<string>(
            "SELECT copyleft FROM spdx_license WHERE identifier = 'GPL-3.0-only'");
        Assert.Equal("strong-copyleft", gpl);

        var agpl = await conn.ExecuteScalarAsync<string>(
            "SELECT copyleft FROM spdx_license WHERE identifier = 'AGPL-3.0-only'");
        Assert.Equal("network-copyleft", agpl);

        var lgpl = await conn.ExecuteScalarAsync<string>(
            "SELECT copyleft FROM spdx_license WHERE identifier = 'LGPL-3.0-only'");
        Assert.Equal("weak-copyleft", lgpl);
    }

    [Fact]
    public async Task SchemaInit_UncategorizedLicense_DefaultsToUnclassified()
    {
        await using var conn = await _db.OpenAsync();
        // CECILL-2.1 is a real SPDX ID not in our curated overlay — sanity-check the default.
        var copyleft = await conn.ExecuteScalarAsync<string?>(
            "SELECT copyleft FROM spdx_license WHERE identifier = 'CECILL-2.1'");
        Assert.Equal("unclassified", copyleft);
    }

    [Fact]
    public async Task SchemaInit_PreservesOsiAndFsfFlags()
    {
        await using var conn = await _db.OpenAsync();
        var mit = await conn.QuerySingleAsync<(long Osi, long Fsf, long Dep)>(
            "SELECT is_osi_approved AS Osi, is_fsf_libre AS Fsf, is_deprecated AS Dep FROM spdx_license WHERE identifier = 'MIT'");
        Assert.Equal(1, mit.Osi);
        Assert.Equal(1, mit.Fsf);
        Assert.Equal(0, mit.Dep);
    }

    [Fact]
    public async Task Seeder_VersionMatch_IsNoOp()
    {
        var seeder = new SpdxLicenseSeeder(NullLogger<SpdxLicenseSeeder>.Instance);
        await using var conn = await _db.OpenAsync();

        // Manually tag one row so we can detect whether the table was truncated.
        await conn.ExecuteAsync(
            "UPDATE spdx_license SET name = 'SENTINEL' WHERE identifier = 'MIT'");

        await seeder.RunAsync(conn);

        var name = await conn.ExecuteScalarAsync<string>(
            "SELECT name FROM spdx_license WHERE identifier = 'MIT'");
        Assert.Equal("SENTINEL", name); // truncate did NOT run
    }

    [Fact]
    public async Task Seeder_VersionMismatch_TruncatesAndReseeds()
    {
        var seeder = new SpdxLicenseSeeder(NullLogger<SpdxLicenseSeeder>.Instance);
        await using var conn = await _db.OpenAsync();

        // Tamper: pretend a different version was previously stored, AND tamper with a row.
        await conn.ExecuteAsync(
            "UPDATE instance_settings SET value = '0.0.0-fake' WHERE key = 'spdx_list_version'");
        await conn.ExecuteAsync(
            "UPDATE spdx_license SET name = 'SENTINEL' WHERE identifier = 'MIT'");

        await seeder.RunAsync(conn);

        var name = await conn.ExecuteScalarAsync<string>(
            "SELECT name FROM spdx_license WHERE identifier = 'MIT'");
        Assert.Equal("MIT License", name); // sentinel wiped — truncate + reseed ran

        var version = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = 'spdx_list_version'");
        Assert.Equal("3.28.0", version);
    }
}
