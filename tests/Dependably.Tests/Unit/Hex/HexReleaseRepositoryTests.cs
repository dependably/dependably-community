using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol.Hex;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The hosted and proxied halves of <c>hex_release</c>: tenant gating on each arm, a hosted
/// release shadowing a cached one of the same version, upsert round-trips, and the retirement and
/// docs flags.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexReleaseRepositoryTests : IAsyncLifetime
{
    private const string InnerChecksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-1', 'org-1')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-2', 'org-2')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static HexReleaseFacts Facts(
        HexRetirementReason? reason = null, string? message = null, bool hasDocs = false, string? config = null,
        IReadOnlyList<string>? buildTools = null, IReadOnlyList<HexRequirement>? requirements = null) =>
        new(
            InnerChecksum.ToLowerInvariant(),
            requirements ?? new List<HexRequirement>(),
            "plug",
            buildTools ?? new List<string>(),
            "~> 1.14",
            reason,
            message,
            hasDocs,
            config);

    [Fact]
    public async Task UpsertHosted_RoundTripsEveryFact_AndUppercasesTheInnerChecksum()
    {
        string versionId = await InsertHostedVersionAsync("org-1", "plug", "1.15.0");
        var repo = new HexReleaseRepository(_db);
        var requirements = new List<HexRequirement>
        {
            new("plug_crypto", "~> 2.0", false, "hexpm", "plug_crypto"),
        };

        await repo.UpsertHostedAsync(
            versionId,
            Facts(HexRetirementReason.Security, "CVE-2026-1", hasDocs: true, config: "{<<\"name\">>,<<\"plug\">>}.",
                buildTools: new List<string> { "mix", "rebar3" }, requirements: requirements));

        var release = await repo.GetHostedAsync("org-1", "plug", "1.15.0");

        Assert.NotNull(release);
        Assert.True(release.Hosted);
        Assert.Equal(versionId, release.OwnerId);
        Assert.Equal("1.15.0", release.Version);
        Assert.Equal(InnerChecksum.ToLowerInvariant(), release.Facts.InnerChecksumHex.ToLowerInvariant());
        Assert.Equal(InnerChecksum.ToUpperInvariant(), release.Facts.InnerChecksumHex);
        Assert.Equal("plug", release.Facts.App);
        Assert.Equal("~> 1.14", release.Facts.Elixir);
        Assert.Equal(new[] { "mix", "rebar3" }, release.Facts.BuildTools);
        Assert.Equal(HexRetirementReason.Security, release.Facts.RetiredReason);
        Assert.Equal("CVE-2026-1", release.Facts.RetiredMessage);
        Assert.True(release.Facts.HasDocs);
        Assert.Equal("{<<\"name\">>,<<\"plug\">>}.", release.Facts.MetadataConfig);
        var requirement = Assert.Single(release.Facts.Requirements);
        Assert.Equal("plug_crypto", requirement.Name);
        Assert.Equal("~> 2.0", requirement.Requirement);
        Assert.NotNull(release.PublishedAt);
    }

    [Fact]
    public async Task UpsertHosted_SecondWrite_ReplacesTheFirst()
    {
        string versionId = await InsertHostedVersionAsync("org-1", "jason", "1.4.1");
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(versionId, Facts(HexRetirementReason.Invalid, "bad", hasDocs: true));

        await repo.UpsertHostedAsync(versionId, Facts());

        var release = await repo.GetHostedAsync("org-1", "jason", "1.4.1");
        Assert.NotNull(release);
        Assert.Null(release.Facts.RetiredReason);
        Assert.Null(release.Facts.RetiredMessage);
        Assert.False(release.Facts.HasDocs);
        Assert.Empty(release.Facts.BuildTools);
        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM hex_release WHERE version_id = @versionId", new { versionId }));
    }

    [Fact]
    public async Task GetHosted_OtherOrgOrUnknownVersion_ReturnsNull()
    {
        string versionId = await InsertHostedVersionAsync("org-1", "plug", "1.15.0");
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(versionId, Facts());

        Assert.Null(await repo.GetHostedAsync("org-2", "plug", "1.15.0"));
        Assert.Null(await repo.GetHostedAsync("org-1", "plug", "9.9.9"));
        Assert.Null(await repo.GetHostedAsync("org-1", "phoenix", "1.15.0"));
    }

    [Fact]
    public async Task ListForPackage_HostedShadowsCachedOfTheSameVersion_AndCachedIsGatedByAccess()
    {
        string hosted = await InsertHostedVersionAsync("org-1", "plug", "1.15.0");
        string cachedSame = await InsertCacheArtifactAsync("plug", "1.15.0", "2026-03-01T00:00:00Z");
        string cachedOnly = await InsertCacheArtifactAsync("plug", "1.14.0", "2026-02-01T00:00:00Z");
        string cachedNoAccess = await InsertCacheArtifactAsync("plug", "1.13.0", null);
        await GrantAccessAsync("org-1", cachedSame);
        await GrantAccessAsync("org-1", cachedOnly);
        await GrantAccessAsync("org-2", cachedNoAccess);
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(hosted, Facts());
        await repo.UpsertCachedAsync(cachedSame, Facts());
        await repo.UpsertCachedAsync(cachedOnly, Facts(HexRetirementReason.Renamed, "use plug2"));
        await repo.UpsertCachedAsync(cachedNoAccess, Facts());

        var releases = await repo.ListForPackageAsync("org-1", "plug");

        Assert.Equal(new[] { "1.15.0", "1.14.0" }, releases.Select(r => r.Version));
        Assert.True(releases[0].Hosted);
        Assert.Equal(hosted, releases[0].OwnerId);
        Assert.False(releases[1].Hosted);
        Assert.Equal(cachedOnly, releases[1].OwnerId);
        Assert.Equal(HexRetirementReason.Renamed, releases[1].Facts.RetiredReason);
        Assert.Equal(new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero), releases[1].PublishedAt);
        Assert.Equal(new[] { "1.13.0" }, (await repo.ListForPackageAsync("org-2", "plug")).Select(r => r.Version));
    }

    [Fact]
    public async Task ListAll_SpansPackagesAndPlanes_WithHostedShadowingCachedPerNameAndVersion()
    {
        string hosted = await InsertHostedVersionAsync("org-1", "plug", "1.15.0");
        string cachedShadowed = await InsertCacheArtifactAsync("plug", "1.15.0", null);
        string cachedJason = await InsertCacheArtifactAsync("jason", "1.4.1", null);
        string cachedPlugOtherVersion = await InsertCacheArtifactAsync("plug", "1.14.0", null);
        await GrantAccessAsync("org-1", cachedShadowed);
        await GrantAccessAsync("org-1", cachedJason);
        await GrantAccessAsync("org-1", cachedPlugOtherVersion);
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(hosted, Facts());
        await repo.UpsertCachedAsync(cachedShadowed, Facts());
        await repo.UpsertCachedAsync(cachedJason, Facts());
        await repo.UpsertCachedAsync(cachedPlugOtherVersion, Facts());

        var all = await repo.ListAllAsync("org-1");

        Assert.Equal(
            new[] { ("plug", "1.15.0", true), ("jason", "1.4.1", false), ("plug", "1.14.0", false) },
            all.Select(x => (x.Name, x.Release.Version, x.Release.Hosted)));
        Assert.Equal(hosted, all[0].Release.OwnerId);
        Assert.Empty(await repo.ListAllAsync("org-2"));
    }

    [Fact]
    public async Task SetRetirement_HostedRelease_SetsThenClears_AndReportsMissingRelease()
    {
        string versionId = await InsertHostedVersionAsync("org-1", "phoenix", "1.7.0");
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(versionId, Facts());

        Assert.True(await repo.SetRetirementAsync("org-1", "phoenix", "1.7.0", HexRetirementReason.Deprecated, "upgrade"));
        var retired = await repo.GetHostedAsync("org-1", "phoenix", "1.7.0");
        Assert.Equal(HexRetirementReason.Deprecated, retired!.Facts.RetiredReason);
        Assert.Equal("upgrade", retired.Facts.RetiredMessage);

        Assert.True(await repo.SetRetirementAsync("org-1", "phoenix", "1.7.0", null, null));
        var cleared = await repo.GetHostedAsync("org-1", "phoenix", "1.7.0");
        Assert.Null(cleared!.Facts.RetiredReason);
        Assert.Null(cleared.Facts.RetiredMessage);

        Assert.False(await repo.SetRetirementAsync("org-2", "phoenix", "1.7.0", HexRetirementReason.Other, null));
        Assert.False(await repo.SetRetirementAsync("org-1", "phoenix", "0.0.1", HexRetirementReason.Other, null));
    }

    [Fact]
    public async Task SetCachedRetirement_UpdatesOnlyTheNamedCacheArtifact()
    {
        string a = await InsertCacheArtifactAsync("ecto", "3.11.0", null);
        string b = await InsertCacheArtifactAsync("ecto", "3.12.0", null);
        await GrantAccessAsync("org-1", a);
        await GrantAccessAsync("org-1", b);
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertCachedAsync(a, Facts());
        await repo.UpsertCachedAsync(b, Facts());

        await repo.SetCachedRetirementAsync(a, HexRetirementReason.Invalid, "broken migration");

        var releases = await repo.ListForPackageAsync("org-1", "ecto");
        Assert.Equal(HexRetirementReason.Invalid, releases.Single(r => r.OwnerId == a).Facts.RetiredReason);
        Assert.Equal("broken migration", releases.Single(r => r.OwnerId == a).Facts.RetiredMessage);
        Assert.Null(releases.Single(r => r.OwnerId == b).Facts.RetiredReason);

        await repo.SetCachedRetirementAsync(a, null, null);
        Assert.Null((await repo.ListForPackageAsync("org-1", "ecto")).Single(r => r.OwnerId == a).Facts.RetiredReason);
    }

    [Fact]
    public async Task SetHasDocs_TogglesTheFlag_AndReportsMissingRelease()
    {
        string versionId = await InsertHostedVersionAsync("org-1", "plug", "1.15.0");
        var repo = new HexReleaseRepository(_db);
        await repo.UpsertHostedAsync(versionId, Facts());

        Assert.True(await repo.SetHasDocsAsync("org-1", "plug", "1.15.0", true));
        Assert.True((await repo.GetHostedAsync("org-1", "plug", "1.15.0"))!.Facts.HasDocs);
        Assert.True(await repo.SetHasDocsAsync("org-1", "plug", "1.15.0", false));
        Assert.False((await repo.GetHostedAsync("org-1", "plug", "1.15.0"))!.Facts.HasDocs);
        Assert.False(await repo.SetHasDocsAsync("org-2", "plug", "1.15.0", true));
    }

    [Theory]
    [InlineData(HexRetirementReason.Other, "other")]
    [InlineData(HexRetirementReason.Invalid, "invalid")]
    [InlineData(HexRetirementReason.Security, "security")]
    [InlineData(HexRetirementReason.Deprecated, "deprecated")]
    [InlineData(HexRetirementReason.Renamed, "renamed")]
    public void ReasonWireForm_RoundTrips(HexRetirementReason reason, string wire)
    {
        Assert.Equal(wire, HexReleaseRepository.ReasonToWire(reason));
        Assert.Equal(reason, HexReleaseRepository.ReasonFromWire(wire));
    }

    [Fact]
    public void ReasonFromWire_NullStaysNull_AndUnknownSpellingIsOther()
    {
        Assert.Null(HexReleaseRepository.ReasonFromWire(null));
        Assert.Equal(HexRetirementReason.Other, HexReleaseRepository.ReasonFromWire("abandoned"));
    }

    private async Task<string> InsertHostedVersionAsync(string orgId, string name, string version)
    {
        string packageId = $"pkg-{orgId}-{name}";
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT OR IGNORE INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@packageId, @orgId, 'hex', @name, @name, 0)",
            new { packageId, orgId, name });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256) " +
            "VALUES (@versionId, @packageId, @version, @purl, @blobKey, @filename, 1024, @checksum)",
            new
            {
                versionId,
                packageId,
                version,
                purl = $"pkg:hex/{name}@{version}",
                blobKey = $"hosted/{orgId}/hex/{name}/{version}/{name}-{version}.tar",
                filename = $"{name}-{version}.tar",
                checksum = InnerChecksum,
            });
        return versionId;
    }

    private async Task<string> InsertCacheArtifactAsync(string name, string version, string? publishedAt)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, published_at)
            VALUES
                (@id, 'hex', @name, @version, @filename, @blobKey, @contentHash, 0, @publishedAt)
            """,
            new
            {
                id,
                name,
                version,
                filename = $"{name}-{version}.tar",
                blobKey = $"proxy/hex/{name}/{version}/{name}-{version}.tar",
                contentHash = $"sha256:{Guid.NewGuid():N}",
                publishedAt,
            });
        return id;
    }

    private async Task GrantAccessAsync(string orgId, string cacheArtifactId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @cacheArtifactId)",
            new { orgId, cacheArtifactId });
    }
}
