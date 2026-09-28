using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Presigned redirects through the real pipeline, for every ecosystem whose artefact serve path
/// calls the redirect seam. Each ecosystem gets the same twins: a redirect once its checks pass,
/// carrying one <c>delivery = redirect</c> usage event for the object's size and the same
/// download tracking the streamed read records; a stream whenever the feature is off, the
/// ecosystem is not listed, the request is ranged, the store cannot sign, or the object is gone;
/// and no URL at all for metadata, a blocked artefact, or an unauthorized caller.
///
/// <para>
/// The store is a <see cref="PresigningBlobStore"/> that records every key it signs, so each
/// refusal asserts that nothing was signed — not only that the status is right. The presign
/// options are swapped per request (the service is resolved per scope from a field), so one
/// factory covers enabled, disabled, and not-listed.
/// </para>
///
/// <para>
/// Hosted artefacts are published through the real publish routes; the proxy-only ecosystems
/// (Go, Cargo, apk, Terraform, Hex) are seeded as a cache hit — the blob under its org-scoped key
/// and the cache-plane row a first fetch records — since a redirect is only ever a cache hit.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PresignedArtifactRedirectTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    private readonly PresigningBlobStore _store;
    private PresignedReadOptions _options = Options(enabled: true, PresignedReadOptions.RedirectableEcosystems);
    private string _orgId = "";
    private string _pullToken = "";
    private bool _rpmPushed;

    public PresignedArtifactRedirectTests()
    {
        _factory = new DependablyFactory
        {
            RpmUpstreamMode = "merged",
            ServiceOverrides = services =>
            {
                services.RemoveAll<IBlobStore>();
                services.AddSingleton<IBlobStore>(_store!);
                services.RemoveAll<TieredBlobStorage>();
                services.AddSingleton(new TieredBlobStorage(_store!, _store!));
                services.RemoveAll<BlobPresignService>();
                services.AddScoped(sp => new BlobPresignService(
                    _options, sp.GetRequiredService<TimeProvider>(), NullLogger<BlobPresignService>.Instance));
            },
        };
        _store = new PresigningBlobStore(_factory.BlobStore);
    }

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        var org = await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync("default");
        _orgId = org!.Id;
        _pullToken = await _factory.CreateToken("pull");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    public static TheoryData<string> Ecosystems => new(PresignedReadOptions.RedirectableEcosystems.Order(StringComparer.Ordinal));

    public static TheoryData<string> BlockableEcosystems =>
        new(PresignedReadOptions.RedirectableEcosystems.Where(e => e != "oci").Order(StringComparer.Ordinal));

    // ── Redirect, metering, and tracking parity ────────────────────────────────

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task Redirects_WithOneRedirectUsageEvent_AndTheSameTrackingAsAStreamedRead(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();

        // Streamed first, presign off: the baseline tracking delta and the object's size.
        _options = Options(enabled: false, PresignedReadOptions.RedirectableEcosystems);
        var before = await TrackingAsync(seeded);
        using var streamed = await client.GetAsync(seeded.Url);
        Assert.Equal(HttpStatusCode.OK, streamed.StatusCode);
        long size = (await streamed.Content.ReadAsByteArrayAsync()).LongLength;
        var afterStream = await TrackingAsync(seeded);
        await ResetEventsAsync();
        _store.ClearSigned();

        _options = Options(enabled: true, PresignedReadOptions.RedirectableEcosystems);
        using var redirected = await client.GetAsync(seeded.Url);

        Assert.Equal(RedirectStatus(ecosystem), redirected.StatusCode);
        Assert.StartsWith(PresigningBlobStore.UrlBase, redirected.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.True(redirected.Headers.CacheControl is { Private: true, NoStore: true },
            $"{ecosystem}: the redirect must be private, no-store; was {redirected.Headers.CacheControl}");
        Assert.Single(_store.Signed);

        var usage = Assert.Single(await DrainEventsAsync());
        Assert.Equal(UsageDelivery.Redirect, usage.Delivery);
        Assert.Equal(UsageMeters.EgressBytes, usage.Meter);
        Assert.Equal(size, usage.Quantity);
        Assert.Equal(ecosystem, usage.Source);

        var afterRedirect = await TrackingAsync(seeded);
        var streamedDelta = afterStream - before;
        Assert.NotEqual(Tracking.Zero, streamedDelta);
        Assert.Equal(streamedDelta, afterRedirect - afterStream);
    }

    // ── Streams whenever a redirect is not certain ─────────────────────────────

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task Streams_WhenDisabled_NotListed_Ranged_OrUnsignable(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();

        _options = Options(enabled: false, PresignedReadOptions.RedirectableEcosystems);
        await AssertStreamsAsync(client, seeded.Url, $"{ecosystem} with presigned reads off");

        var everyOtherEcosystem = PresignedReadOptions.RedirectableEcosystems.Where(e => e != ecosystem).ToHashSet(StringComparer.Ordinal);
        _options = Options(enabled: true, everyOtherEcosystem);
        await AssertStreamsAsync(client, seeded.Url, $"{ecosystem} not on the list");

        _options = Options(enabled: true, PresignedReadOptions.RedirectableEcosystems);
        _store.CanSign = false;
        await AssertStreamsAsync(client, seeded.Url, $"{ecosystem} on a store that cannot sign");
        _store.CanSign = true;

        using var ranged = new HttpRequestMessage(HttpMethod.Get, seeded.Url);
        ranged.Headers.Range = new RangeHeaderValue(0, 0);
        using var rangedResponse = await client.SendAsync(ranged);
        Assert.True(rangedResponse.StatusCode is HttpStatusCode.OK or HttpStatusCode.PartialContent,
            $"{ecosystem}: a ranged read streams; was {(int)rangedResponse.StatusCode}");
        Assert.Empty(_store.Signed);
    }

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task Streams_OrFallsThrough_WhenTheObjectIsMissingFromTheStore(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();

        // Learn the key the serve path signs, then take the bytes away behind the row.
        using (var first = await client.GetAsync(seeded.Url))
        {
            Assert.Equal(RedirectStatus(ecosystem), first.StatusCode);
        }

        string key = Assert.Single(_store.Signed);
        await using var saved = await _store.Inner.GetAsync(key);
        var bytes = new MemoryStream();
        await saved!.CopyToAsync(bytes);
        await _store.Inner.DeleteAsync(key);
        _store.ClearSigned();

        try
        {
            using var response = await client.GetAsync(seeded.Url);
            AssertNotRedirected(response);
            Assert.Empty(_store.Signed);
        }
        finally
        {
            bytes.Position = 0;
            await _store.Inner.PutAsync(key, bytes);
        }
    }

    // ── Never a URL ────────────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task Metadata_NeverRedirects(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();

        using var response = await client.GetAsync(seeded.MetadataUrl);

        AssertNotRedirected(response);
        Assert.Empty(_store.Signed);
    }

    [Theory]
    [MemberData(nameof(BlockableEcosystems))]
    public async Task Blocked_NeverRedirects(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();
        await seeded.SetBlockedAsync(true);

        try
        {
            using var response = await client.GetAsync(seeded.Url);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(_store.Signed);
        }
        finally
        {
            await seeded.SetBlockedAsync(false);
        }
    }

    [Theory]
    [MemberData(nameof(Ecosystems))]
    public async Task Unauthorized_NeverRedirects(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var anonymous = Client(authenticated: false);

        using var response = await anonymous.GetAsync(seeded.Url);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_store.Signed);
    }

    /// <summary>
    /// A yank hides a version from resolution; no ecosystem refuses the download of a yanked
    /// version's bytes (a lockfile pinned to it must still install). The redirect is the same
    /// decision as the stream, so a yanked artefact redirects exactly when it would have streamed.
    /// </summary>
    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    public async Task Yanked_FollowsTheStreamingDecision(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        await seeded.YankAsync!();
        using var client = Client();

        _options = Options(enabled: false, PresignedReadOptions.RedirectableEcosystems);
        using var streamed = await client.GetAsync(seeded.Url);
        _options = Options(enabled: true, PresignedReadOptions.RedirectableEcosystems);
        using var redirected = await client.GetAsync(seeded.Url);

        Assert.Equal(HttpStatusCode.OK, streamed.StatusCode);
        Assert.Equal(RedirectStatus(ecosystem), redirected.StatusCode);
    }

    /// <summary>
    /// apk-tools follows a 302 but not a 307, so apk artefacts redirect with 302; every other
    /// ecosystem gets a 307. Spelled out here rather than read from the service, so a change to
    /// either side fails this suite.
    /// </summary>
    private static HttpStatusCode RedirectStatus(string ecosystem)
        => ecosystem == "apk" ? HttpStatusCode.Found : HttpStatusCode.TemporaryRedirect;

    private static void AssertNotRedirected(HttpResponseMessage response)
        => Assert.True(
            response.StatusCode is not (HttpStatusCode.TemporaryRedirect or HttpStatusCode.Found),
            $"expected no presigned redirect, was {(int)response.StatusCode}");

    // ── Seeding ────────────────────────────────────────────────────────────────

    /// <summary>
    /// A seeded artefact: its download and metadata URLs, the substring every row that tracks it
    /// carries (its purl or cache-plane name), and how to block and yank it.
    /// </summary>
    private sealed record Seeded(
        string Url, string MetadataUrl, string Marker, Func<bool, Task> SetBlockedAsync, Func<Task>? YankAsync = null);

    private async Task<Seeded> SeedAsync(string ecosystem)
    {
        _store.ClearSigned();
        _store.CanSign = true;
        _options = Options(enabled: true, PresignedReadOptions.RedirectableEcosystems);
        string u = "ps" + Guid.NewGuid().ToString("N")[..10];

        switch (ecosystem)
        {
            case "npm":
                await _factory.PushNpmPackage(u, "1.0.0");
                return Hosted($"/npm/tarballs/{u}/{u}-1.0.0.tgz", $"/npm/{u}", u, "npm");

            case "pypi":
                {
                    await _factory.PushPyPiPackage(u, "1.0.0");
                    using var client = Client();
                    string index = await client.GetStringAsync($"/simple/{u}/");
                    string href = index.Split("href=\"")[1].Split('"')[0].Split('#')[0];
                    return Hosted(href, $"/simple/{u}/", u, "pypi");
                }

            case "nuget":
                await _factory.PushNuGetPackage(u, "1.0.0");
                return Hosted($"/nuget/flatcontainer/{u}/1.0.0/{u}.1.0.0.nupkg", $"/nuget/flatcontainer/{u}/index.json", u, "nuget");

            case "maven":
                string jar = await _factory.PushMavenArtifact($"com.{u}", "lib", "1.0.0");
                return Hosted($"/maven/com/{u}/lib/1.0.0/{jar}", $"/maven/com/{u}/lib/maven-metadata.xml", u, "maven");

            case "rpm":
                // The synthetic RPM has a fixed NEVRA, so it is published once per factory.
                if (!_rpmPushed)
                {
                    await _factory.PushRpmPackage();
                    _rpmPushed = true;
                }

                return Hosted("/rpm/packages/testpkg-1.0-1.x86_64.rpm", "/rpm/repodata/repomd.xml", "testpkg", "rpm");

            case "oci":
                return await SeedOciAsync(u);

            case "go":
                {
                    string module = $"example.com/{u}";
                    await SeedCacheHitAsync("golang", module, "v1.0.0", "v1.0.0.zip", BlobKeys.Go(_orgId, module, "v1.0.0", "zip"));
                    await PutBytesAsync(BlobKeys.Go(_orgId, module, "v1.0.0", "info"), """{"Version":"v1.0.0"}"""u8.ToArray());
                    return Proxied($"/go/{module}/@v/v1.0.0.zip", $"/go/{module}/@v/v1.0.0.info", module);
                }

            case "cargo":
                await SeedCacheHitAsync("cargo", u, "1.0.0", $"{u}-1.0.0.crate", BlobKeys.Cargo(_orgId, u, "1.0.0"));
                return Proxied($"/cargo/api/v1/crates/{u}/1.0.0/download", $"/cargo/{u[..2]}/{u[2..4]}/{u}", u);

            case "apk":
                {
                    string file = $"{u}-1.0.0-r0.apk";
                    await SeedCacheHitAsync("apk", u, "1.0.0-r0", $"main/x86_64/{file}", BlobKeys.Apk(_orgId, "v3.19", "main", "x86_64", file));
                    return Proxied($"/apk/v3.19/main/x86_64/{file}", "/apk/v3.19/main/x86_64/APKINDEX.tar.gz", u);
                }

            case "terraform":
                {
                    string provider = $"registry.terraform.io/{u}/null";
                    await SeedCacheHitAsync("terraform", provider, "1.0.0", "linux_amd64.zip",
                        BlobKeys.Terraform(_orgId, "registry.terraform.io", u, "null", "1.0.0", "linux_amd64"));
                    return Proxied($"/terraform/{provider}/1.0.0/linux_amd64.zip", $"/terraform/{provider}/index.json", u);
                }

            case "hex":
                await SeedCacheHitAsync("hex", u, "1.0.0", $"{u}-1.0.0.tar", BlobKeys.Hex(_orgId, u, "1.0.0"));
                return Proxied($"/hex/tarballs/{u}-1.0.0.tar", $"/hex/packages/{u}", u);

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No seed for this ecosystem.");
        }
    }

    private Seeded Hosted(string url, string metadataUrl, string marker, string ecosystem)
        => new(url, metadataUrl, marker,
            blocked => SetHostedBlockAsync(marker, blocked),
            () => _factory.SetVersionYanked("default", ecosystem, marker, "1.0.0", "compromised"));

    private Seeded Proxied(string url, string metadataUrl, string marker)
        => new(url, metadataUrl, marker, blocked => SetProxiedBlockAsync(marker, blocked));

    private async Task<Seeded> SeedOciAsync(string u)
    {
        string repo = $"presign/{u}";
        byte[] layer = RandomNumberGenerator.GetBytes(256);
        string digest = "sha256:" + Convert.ToHexString(SHA256.HashData(layer)).ToLowerInvariant();

        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        using var created = await push.PostAsync($"/v2/{repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(layer));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        // OCI's block gate is its licence arm, an org-wide policy this shared factory cannot flip
        // without blocking every other ecosystem's artefacts; its block twin is in
        // OciBlobPresignRedirectTests.
        return new Seeded($"/v2/{repo}/blobs/{digest}", $"/v2/{repo}/tags/list", repo,
            _ => throw new NotSupportedException("OCI's block twin lives in OciBlobPresignRedirectTests."));
    }

    private async Task SeedCacheHitAsync(string ecosystem, string name, string version, string filename, string blobKey)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(64);
        await PutBytesAsync(blobKey, bytes);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            _orgId, ecosystem, name, version, filename,
            Sha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            SizeBytes: bytes.Length, BlobKey: blobKey,
            UpstreamUrl: $"https://upstream.example/{filename}", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(id);
    }

    private Task PutBytesAsync(string key, byte[] bytes) => _store.Inner.PutAsync(key, new MemoryStream(bytes));

    private async Task SetHostedBlockAsync(string marker, bool blocked)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = @state
            WHERE package_id IN (SELECT id FROM packages WHERE org_id = @orgId AND (name LIKE @like OR purl_name LIKE @like))
            """,
            new { state = blocked ? "blocked" : null, orgId = _orgId, like = $"%{marker}%" });
    }

    private async Task SetProxiedBlockAsync(string marker, bool blocked)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE tenant_artifact_access SET manual_block_state = @state
            WHERE org_id = @orgId AND cache_artifact_id IN (SELECT id FROM cache_artifact WHERE name LIKE @like)
            """,
            new { state = blocked ? "blocked" : null, orgId = _orgId, like = $"%{marker}%" });
    }

    // ── Tracking ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Everything a download is tracked by: activity rows naming the artefact, the hosted
    /// download counter, and the cache plane's per-tenant download and access counters.
    /// </summary>
    private readonly record struct Tracking(long Activity, long HostedDownloads, long CacheDownloads, long CacheAccesses)
    {
        public static Tracking Zero => default;

        public static Tracking operator -(Tracking a, Tracking b) => new(
            a.Activity - b.Activity, a.HostedDownloads - b.HostedDownloads,
            a.CacheDownloads - b.CacheDownloads, a.CacheAccesses - b.CacheAccesses);
    }

    private async Task<Tracking> TrackingAsync(Seeded seeded)
    {
        await FlushWritersAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        string like = $"%{seeded.Marker}%";
        return new Tracking(
            await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND purl LIKE @like",
                new { orgId = _orgId, like }),
            await conn.ExecuteScalarAsync<long>(
                """
                SELECT COALESCE(SUM(pv.download_count), 0) FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId AND pv.purl LIKE @like
                """,
                new { orgId = _orgId, like }),
            await conn.ExecuteScalarAsync<long>(
                """
                SELECT COALESCE(SUM(taa.download_count), 0) FROM tenant_artifact_access taa
                JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                WHERE taa.org_id = @orgId AND ca.name LIKE @like
                """,
                new { orgId = _orgId, like }),
            await conn.ExecuteScalarAsync<long>(
                """
                SELECT COALESCE(SUM(taa.access_count), 0) FROM tenant_artifact_access taa
                JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
                WHERE taa.org_id = @orgId AND ca.name LIKE @like
                """,
                new { orgId = _orgId, like }));
    }

    private async Task FlushWritersAsync()
    {
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync(TimeSpan.FromSeconds(10));
        await _factory.Services.GetRequiredService<DownloadCountWriterHostedService>().WaitForIdleAsync(TimeSpan.FromSeconds(10));
        await _factory.Services.GetRequiredService<UsageEventWriterHostedService>().WaitForIdleAsync(TimeSpan.FromSeconds(10));
    }

    private async Task ResetEventsAsync()
    {
        await FlushWritersAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("DELETE FROM usage_events WHERE 1 = 1");
    }

    private async Task<List<UsageEvent>> DrainEventsAsync()
    {
        await FlushWritersAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        var rows = await conn.QueryAsync<UsageEvent>(
            """
            SELECT event_id AS EventId, org_id AS OrgId, meter AS Meter, delivery AS Delivery,
                   quantity AS Quantity, source AS Source, object_ref AS ObjectRef, occurred_at AS OccurredAt
            FROM usage_events
            """);
        return rows.ToList();
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task AssertStreamsAsync(HttpClient client, string url, string because)
    {
        _store.ClearSigned();
        using var response = await client.GetAsync(url);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{because}: expected a streamed 200, was {(int)response.StatusCode}");
        Assert.Empty(_store.Signed);
    }

    private HttpClient Client(bool authenticated = true)
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (authenticated)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _pullToken);
        }

        return client;
    }

    private static PresignedReadOptions Options(bool enabled, IReadOnlySet<string> ecosystems)
        => new() { Enabled = enabled, Ttl = TimeSpan.FromSeconds(60), Ecosystems = ecosystems };
}
