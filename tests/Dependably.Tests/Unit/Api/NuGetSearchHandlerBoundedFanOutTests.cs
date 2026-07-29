using System.Data.Common;
using System.Text.Json;
using Dapper;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Pins the fix for the totalHits fan-out regression in <see cref="NuGetSearchHandler"/>:
/// computing the true match count must not fall back to walking every name-matching package's
/// full combined version list (2-3 DB round trips each via
/// <see cref="ArtifactInventoryRepository.ListServeableVersionsAsync"/>). An empty/broad query
/// matches an org's entire NuGet catalogue, so that fan-out scales per-request DB round trips
/// with org size rather than with the requested page — reachable anonymously when
/// AnonymousPull is enabled.
///
/// Mixed partial-failure: the seeded catalogue has both packages with a listed version and
/// packages whose only version is yanked (no listed version), interleaved by name so the
/// returned page includes an unmatched package that gets silently dropped, exactly like the
/// pre-regression behavior — this is not an all-pass or all-fail batch.
///
/// Each test asserts totalHits reflects the full match count, AND that the number of
/// <see cref="IMetadataStore.OpenAsync"/> calls stays bounded by the page size, not the org's
/// full package count, via a counting <see cref="IMetadataStore"/> decorator. On the regressed
/// code (looping <c>LoadCombinedVersionsAsync</c> over the entire filtered set to compute
/// totalHits) the open count scales with the seeded package count and blows the bound; on the
/// fix it stays flat regardless of how many packages the org holds.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NuGetSearchHandlerBoundedFanOutTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private const int TotalPackages = 40;
    private const int Take = 5;

    // Every 5th package (by seed index) has only a yanked version — no listed version — so it
    // is excluded from both totalHits and the returned page, while still costing the page loop
    // a version lookup when it falls inside the requested window.
    private const int UnmatchedStride = 5;

    [Fact]
    public async Task SearchAsync_TotalHitsCorrect_AndVersionFanOutBoundedByPageSize()
    {
        string orgId = await SeedOrgWithMixedPackagesAsync("search");
        var (handler, countingDb) = BuildHandler();

        var httpContext = NewAnonymousHttpContext();
        var result = await handler.SearchAsync(
            httpContext, orgId, q: "boundedfanout", skip: 0, take: Take,
            prerelease: false, ct: CancellationToken.None);

        var jsonResult = Assert.IsType<JsonResult>(result);
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(jsonResult.Value));

        int totalHits = doc.RootElement.GetProperty("totalHits").GetInt32();
        int dataCount = doc.RootElement.GetProperty("data").GetArrayLength();

        int expectedMatches = TotalPackages - TotalPackages / UnmatchedStride;
        Assert.Equal(expectedMatches, totalHits);
        // The first window item (index 0) is the unmatched (yanked-only) package, so the
        // returned page shrinks below `take` — the page-shrink behavior a raw Skip/Take window
        // has always had, preserved by the fix.
        Assert.True(dataCount < Take, $"expected a shrunk page below {Take}, got {dataCount}");

        AssertBoundedByPageSize(countingDb, Take);
    }

    [Fact]
    public async Task AutocompleteAsync_TotalHitsCorrect_AndVersionFanOutBoundedByPageSize()
    {
        string orgId = await SeedOrgWithMixedPackagesAsync("autocomplete");
        var (handler, countingDb) = BuildHandler();

        var httpContext = NewAnonymousHttpContext();
        var query = new NuGetAutocompleteParams(
            Q: "boundedfanout", Id: null, Skip: 0, Take: Take, Prerelease: false);
        var result = await handler.AutocompleteAsync(httpContext, orgId, query, CancellationToken.None);

        var jsonResult = Assert.IsType<JsonResult>(result);
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(jsonResult.Value));

        int totalHits = doc.RootElement.GetProperty("totalHits").GetInt32();
        int dataCount = doc.RootElement.GetProperty("data").GetArrayLength();

        int expectedMatches = TotalPackages - TotalPackages / UnmatchedStride;
        Assert.Equal(expectedMatches, totalHits);
        Assert.True(dataCount < Take, $"expected a shrunk page below {Take}, got {dataCount}");

        AssertBoundedByPageSize(countingDb, Take);
    }

    // On the regressed code the open count scales with TotalPackages (40 * 2 = 80+); on the fix
    // it stays a small constant plus 2 opens per page item, independent of org size.
    private static void AssertBoundedByPageSize(CountingMetadataStore countingDb, int take)
    {
        int bound = 4 + (2 * take);
        Assert.True(
            countingDb.OpenCount <= bound,
            $"expected DB opens bounded by page size (<= {bound}), got {countingDb.OpenCount} " +
            $"— the per-package version fan-out is scaling with the org's full package count again.");
    }

    private async Task<string> SeedOrgWithMixedPackagesAsync(string label)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{label}-{Guid.NewGuid():N}");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId });
        }

        for (int i = 0; i < TotalPackages; i++)
        {
            string name = $"boundedfanout-{i:D3}";
            string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "nuget", name);
            bool unmatched = i % UnmatchedStride == 0;
            await PackageSeeder.InsertVersionAsync(
                _db, pkgId, "1.0.0", $"pkg:nuget/{name}@1.0.0");
            if (unmatched)
            {
                await using var conn = await _db.OpenAsync();
                await conn.ExecuteAsync(
                    "UPDATE package_versions SET yanked = 1 WHERE package_id = @pkgId",
                    new { pkgId });
            }
        }

        return orgId;
    }

    private (NuGetSearchHandler Handler, CountingMetadataStore CountingDb) BuildHandler()
    {
        var countingDb = new CountingMetadataStore(_db);
        var orgs = new OrgRepository(countingDb);
        var packages = new PackageRepository(countingDb);
        var cacheArtifacts = new CacheArtifactRepository(countingDb);
        var vulns = new VulnerabilityRepository(countingDb, TestTime.Frozen());
        var inventory = new ArtifactInventoryRepository(countingDb, packages, cacheArtifacts, vulns);
        var tokens = new TokenRepository(countingDb, TestTime.Frozen());
        var urls = new RequestPublicUrlBuilder(new ConfigurationBuilder().Build());
        var handler = new NuGetSearchHandler(orgs, packages, inventory, tokens, urls);

        // Reset after seeding so only the handler call's own opens are counted.
        countingDb.Reset();
        return (handler, countingDb);
    }

    private static DefaultHttpContext NewAnonymousHttpContext()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Host = new HostString("registry.test");
        httpContext.Request.Scheme = "http";
        return httpContext;
    }

    private sealed class CountingMetadataStore : IMetadataStore
    {
        private readonly IMetadataStore _inner;
        private int _openCount;

        public CountingMetadataStore(IMetadataStore inner) => _inner = inner;

        public DbProvider Provider => _inner.Provider;

        public int OpenCount => _openCount;

        public void Reset() => Interlocked.Exchange(ref _openCount, 0);

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            Interlocked.Increment(ref _openCount);
            return await _inner.OpenAsync(ct);
        }
    }
}
