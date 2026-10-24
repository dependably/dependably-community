using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The window between the Maven metadata handler's rendering decision (proxy settings,
/// registries, reservation) and its cache write. Each test drives a real org-state change into
/// that window through <see cref="DecisionGapCache"/>, whose cache lookup is the first thing the
/// handler does after deciding, then asserts what the next request is served.
/// </summary>
public sealed partial class MavenControllerProxyTests
{
    private const string RaceGroupId = "com.acme";
    private const string RaceGroupPrefix = "com/acme";

    [Fact]
    public async Task Metadata_ReservationAddedBetweenDecisionAndRebuild_NextRequestServesNoUpstreamVersions()
    {
        const string artifactId = "internal";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");

        var (cache, epoch, memory) = NewDecisionGapCache();
        var reserved = new ReservedNamespaceService(_db, memory, TimeProvider.System, epoch);
        cache.RunOnceBeforeNextLookup(() => RunBlocking(
            () => reserved.AddAsync(_orgId, "maven", RaceGroupId, _userId)));

        // The request had already decided the name was unreserved, so it merges upstream.
        string[] first = await MetadataVersionsAsync(artifactPath, cache, reserved);
        Assert.Contains("9.9.9", first);

        string[] second = await MetadataVersionsAsync(artifactPath, cache, reserved);
        Assert.Equal(["1.0"], second);

        // The sidecar hashes the document the reserved path serves, not the stored merged one.
        var sidecar = Assert.IsType<ContentResult>(
            await BuildController(CleanOsv(), metadataCache: cache, reservedNamespaces: reserved)
                .Download(artifactPath + "/maven-metadata.xml.sha1", CancellationToken.None));
        string localDoc = Assert.IsType<ContentResult>(
            await BuildController(CleanOsv(), metadataCache: cache, reservedNamespaces: reserved)
                .Download(artifactPath + "/maven-metadata.xml", CancellationToken.None)).Content!;
        Assert.Equal(
            Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(localDoc))).ToLowerInvariant(),
            sidecar.Content);
    }

    [Fact]
    public async Task Metadata_ProxySettingsChangedBetweenDecisionAndRebuild_NextRequestRendersTheNewPolicy()
    {
        const string artifactId = "settings";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "2.0");
        await DeprecateLocalVersionAsync(RaceGroupId, artifactId, "1.0");

        var (cache, epoch, memory) = NewDecisionGapCache();
        var reserved = new ReservedNamespaceService(_db, memory, TimeProvider.System, epoch);

        // What the proxy-settings PUT does: commit the new policy, then bump the org's epoch.
        cache.RunOnceBeforeNextLookup(() => RunBlocking(async () =>
        {
            await SetBlockDeprecatedAsync("block_all");
            epoch.Invalidate(_orgId);
        }));

        // Rendered with the settings read before the change: the deprecated version is listed.
        string[] first = await MetadataVersionsAsync(artifactPath, cache, reserved);
        Assert.Equal(["1.0", "2.0"], first);

        string[] second = await MetadataVersionsAsync(artifactPath, cache, reserved);
        Assert.Equal(["2.0"], second);
    }

    /// <summary>
    /// Adversarial twin of the two tests above: with nothing landing in the window for this org
    /// (only another org's epoch moves), the merged document is cached and reused, so the
    /// pre-captured token does not expire entries it has no reason to.
    /// </summary>
    [Fact]
    public async Task Metadata_NoChangeForThisOrgInTheWindow_MergedDocumentIsCachedAndReused()
    {
        const string artifactId = "steady";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");

        var (cache, epoch, memory) = NewDecisionGapCache();
        var reserved = new ReservedNamespaceService(_db, memory, TimeProvider.System, epoch);
        cache.RunOnceBeforeNextLookup(() => epoch.Invalidate("some-other-org"));

        string[] first = await MetadataVersionsAsync(artifactPath, cache, reserved);
        string[] second = await MetadataVersionsAsync(artifactPath, cache, reserved);

        Assert.Equal(["1.0", "9.9.9"], first);
        Assert.Equal(first, second);
        Assert.Equal(1, UpstreamMetadataGetCount(artifactPath));
    }

    /// <summary>
    /// A reservation added on another replica never touches this replica's epoch, so only the key
    /// separates the two decisions: once this replica's reservation list catches up and a request
    /// decides local-only, it must not be answered by the merged document stored earlier.
    /// </summary>
    [Fact]
    public async Task Metadata_ReservationWithoutEpochBump_LocalDecisionNeverReadsTheMergedDocument()
    {
        const string artifactId = "peer";
        string artifactPath = $"{RaceGroupPrefix}/{artifactId}";
        await PublishLocalVersionAsync(RaceGroupId, artifactId, "1.0");
        StubUpstreamMetadata(artifactPath, "9.9.9");

        string[] first = await MetadataVersionsAsync(artifactPath);
        Assert.Contains("9.9.9", first);

        await ReserveMavenNamespaceAsync(RaceGroupId);

        string[] second = await MetadataVersionsAsync(artifactPath);
        Assert.Equal(["1.0"], second);
    }

    private async Task<string[]> MetadataVersionsAsync(
        string artifactPath,
        RenderedResponseCache<MavenMetadataKey>? cache = null,
        ReservedNamespaceService? reserved = null)
    {
        var result = await BuildController(CleanOsv(), metadataCache: cache, reservedNamespaces: reserved)
            .Download(artifactPath + "/maven-metadata.xml", CancellationToken.None);
        var content = Assert.IsType<ContentResult>(result);
        return XDocument.Parse(content.Content!)
            .Descendants("version")
            .Select(v => v.Value)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private async Task DeprecateLocalVersionAsync(string groupId, string artifactId, string version)
    {
        await using var conn = await _db.OpenAsync();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE package_versions SET deprecated = 'superseded'
            WHERE version = @version
              AND package_id IN (
                  SELECT id FROM packages
                  WHERE org_id = @org AND ecosystem = 'maven' AND purl_name = @purlName)
            """,
            new { version, org = _orgId, purlName = $"{groupId}:{artifactId}" });
        Assert.Equal(1, rows);
    }

    private async Task SetBlockDeprecatedAsync(string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_deprecated = @mode WHERE org_id = @org",
            new { mode, org = _orgId });
    }

    private static (DecisionGapCache Cache, OrgCacheEpochStore Epoch, MemoryCache Memory) NewDecisionGapCache()
    {
        var memory = new MemoryCache(new MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 });
        var epoch = new OrgCacheEpochStore();
        return (new DecisionGapCache(memory, epoch), epoch, memory);
    }

    // The hook runs inside a synchronous cache lookup; Task.Run keeps the awaited work off the
    // test's synchronization context so blocking on it cannot deadlock.
    private static void RunBlocking(Func<Task> work) => Task.Run(work).GetAwaiter().GetResult();

    /// <summary>
    /// The production cache with a one-shot hook on its lookup. The handler's first cache call
    /// after its rendering decision is <see cref="RenderedResponseCache{TKey}.GetOrRebuildAsync"/>,
    /// which looks the key up before running the rebuild, so the hook lands exactly in the gap
    /// between deciding and rendering.
    /// </summary>
    private sealed class DecisionGapCache(IMemoryCache memory, OrgCacheEpochStore epoch)
        : RenderedResponseCache<MavenMetadataKey>(memory, MetadataCacheKeys.MavenMetadata, epoch)
    {
        private Action? _beforeNextLookup;

        public void RunOnceBeforeNextLookup(Action hook) => _beforeNextLookup = hook;

        public override bool TryGet(MavenMetadataKey key, out byte[]? value)
        {
            Interlocked.Exchange(ref _beforeNextLookup, null)?.Invoke();
            return base.TryGet(key, out value);
        }
    }
}
