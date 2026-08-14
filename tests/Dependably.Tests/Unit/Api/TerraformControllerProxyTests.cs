using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Fetch-path behaviour for <see cref="TerraformController"/>, driven end to end against a
/// recording HTTP handler: what credential each upstream request carries, what status an upstream
/// refusal or outage surfaces to the client, what authority a fetched provider is pinned to, what
/// a version document publishes, and what a cache hit records.
///
/// These are the properties a static reading of the controller cannot settle. The credential one in
/// particular has two halves that pull in opposite directions — an authenticated master must
/// receive it, and a discovered third-party release host must not — so each is asserted with its
/// adversarial twin rather than on its own.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerraformControllerProxyTests : IAsyncLifetime
{
    private const string MasterBase = "https://master.example.test/terraform";
    private const string MasterToken = "edge-master-token";
    private const string RegistryHost = "tf.example.test";
    private const string RegistryBase = "https://tf.example.test";
    private const string RegistryToken = "registry-token";
    private const string ReleaseHost = "https://releases.example.test";

    private const string Provider = "tf.example.test/acme/internal";
    private const string Version = "1.2.3";
    private const string Platform = "linux_amd64";

    /// <summary>SHA-256 of the literal <c>provider-archive-bytes</c> the registry tests serve, so a
    /// realistic registry <c>shasum</c> (the protocol mandates one) both verifies and satisfies the
    /// no-checksum-on-a-foreign-host refusal guard.</summary>
    private const string ArchiveShasum = "b5b2b8ae6aade095e7dde6e218993b256794a7fea65fd26a40db1ccf97647729";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly RecordingHandler _http = new();
    private readonly Dependably.Tests.Infrastructure.StubPerOrgTrustAnchorStore _trustStore = new();

    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, "tf-proxy-org");

        // The controller's own AnonymousPull gate would answer 401 before any fetch path runs:
        // these tests drive it directly with no Authorization header of their own.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId", new { orgId = _orgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── The upstream credential ──────────────────────────────────────────────

    [Fact]
    public async Task MirrorMetadataRequest_CarriesTheConfiguredCredential()
    {
        // The chained-edge default topology: the master is seeded with a bearer token and has
        // anonymous pull off, so an anonymous request to it is a 401 on every document.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: MasterToken);
        _http.Route($"{MasterBase}/{Provider}/index.json", Json("""{"versions":{"1.2.3":{}}}"""));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        Assert.IsType<ContentResult>(result);
        Assert.Equal(
            $"Bearer {MasterToken}",
            _http.AuthorizationFor($"{MasterBase}/{Provider}/index.json"));
    }

    [Fact]
    public async Task MirrorArchiveFetch_CarriesTheConfiguredCredential()
    {
        // The archive lives beneath the master's own base on the mirror path, so the credential
        // belongs on it too — this is the request that actually moves the bytes.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: MasterToken);
        byte[] archive = Encoding.UTF8.GetBytes("provider-archive-bytes");
        _http.Route(
            $"{MasterBase}/{Provider}/{Version}.json",
            MirrorVersionDocument(hashes: null));
        _http.Route($"{MasterBase}/{Provider}/{Version}/linux_amd64.zip", Bytes(archive));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal(
            $"Bearer {MasterToken}",
            _http.AuthorizationFor($"{MasterBase}/{Provider}/{Version}/linux_amd64.zip"));
    }

    [Fact]
    public async Task RegistryArchiveOnADiscoveredHost_DoesNotCarryTheCredential()
    {
        // The adversarial twin of the two above. On the registry protocol the download_url names a
        // host the upstream chose, not one the operator configured — releases.hashicorp.com for
        // HashiCorp's providers. The org's credential must reach the registry and stop there;
        // sending it on would turn a private-registry token into a third-party disclosure.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: RegistryToken);
        byte[] archive = Encoding.UTF8.GetBytes("provider-archive-bytes");
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{downloadUrl}}","shasum":"{{ArchiveShasum}}"}"""));
        _http.Route(downloadUrl, Bytes(archive));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal(
            $"Bearer {RegistryToken}",
            _http.AuthorizationFor($"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64"));
        Assert.Null(_http.AuthorizationFor(downloadUrl));
    }

    // ── The upstream-refusal contract ────────────────────────────────────────

    [Theory]
    // An authenticated upstream refusing the credential is a deterministic verdict: no retry helps,
    // and reporting it as "provider not found" is what makes a broken chain invisible.
    [InlineData(HttpStatusCode.Unauthorized, StatusCodes.Status502BadGateway)]
    [InlineData(HttpStatusCode.Forbidden, StatusCodes.Status502BadGateway)]
    // An outage is retryable and is not a statement about whether the provider exists.
    [InlineData(HttpStatusCode.InternalServerError, StatusCodes.Status503ServiceUnavailable)]
    [InlineData(HttpStatusCode.BadGateway, StatusCodes.Status503ServiceUnavailable)]
    public async Task UpstreamRefusalOrOutage_DoesNotCollapseIntoNotFound(
        HttpStatusCode upstreamStatus, int expected)
    {
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: MasterToken);
        _http.Route($"{MasterBase}/{Provider}/index.json", () => new HttpResponseMessage(upstreamStatus));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        Assert.Equal(expected, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task UpstreamNotFound_StaysNotFound()
    {
        // The twin that keeps the mapping honest: a genuine 404 is how a registry reports a
        // provider it does not carry, and the mirror protocol expects a 404 back for it.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: MasterToken);
        _http.Route($"{MasterBase}/{Provider}/index.json", () => new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        Assert.IsType<NotFoundResult>(result);
    }

    // ── Going through the shared upstream path ───────────────────────────────

    [Fact]
    public async Task AirGapped_RefusesMetadataEgressInsteadOfReachingUpstream()
    {
        // Metadata reads go through UpstreamClient, which is where air-gap enforcement, the URL
        // validator and the 32 MB body cap live. A raw named client has none of them, and the
        // symptom of bypassing it is the quietest one: an air-gapped instance still egressing.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route($"{MasterBase}/{Provider}/index.json", Json("""{"versions":{"1.2.3":{}}}"""));

        var controller = BuildController(airGapped: true);

        await Assert.ThrowsAsync<AirGappedException>(
            () => controller.HandleMirrorRequest($"{Provider}/index.json", default));
        Assert.Empty(_http.Urls);
    }

    // ── Source pinning ───────────────────────────────────────────────────────

    [Fact]
    public async Task ArchiveFetch_PinsTheRegistryAuthorityNotTheReleaseHost()
    {
        // The pin is the dependency-confusion control the mirror's recorded posture is built on.
        // Pinning on the download_url would bind every provider to one shared release CDN, which
        // names no provider identity; the registry that resolved the address is the authority.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        byte[] archive = Encoding.UTF8.GetBytes("provider-archive-bytes");
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{downloadUrl}}","shasum":"{{ArchiveShasum}}"}"""));
        _http.Route(downloadUrl, Bytes(archive));

        var result = await BuildController(sourcePinning: true).HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        string? pinned = await new SourcePinRepository(_db, new ConfigurationBuilder().Build())
            .GetPinnedHostAsync(_orgId, "terraform", Provider);
        Assert.Equal(RegistryBase, pinned);
    }

    // ── Version documents ────────────────────────────────────────────────────

    [Fact]
    public async Task VersionDocument_PublishesTheZipHashOfACachedArchive()
    {
        // A chained edge takes its only fetch-time checksum from this field. With it absent the
        // edge hashes whatever bytes arrived, stores them, and re-serves them as authoritative —
        // the client-side lock file that the mirror's integrity argument rests on does not protect
        // an intermediate cache.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route(
            $"{MasterBase}/{Provider}/{Version}.json",
            MirrorVersionDocument(hashes: null));

        string sha = new('a', 64);
        await SeedCachedArchiveAsync(sha);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var hashes = archives.GetProperty("linux_amd64").GetProperty("hashes");
        Assert.Equal($"zh:{sha}", Assert.Single(hashes.EnumerateArray()).GetString());
    }

    [Fact]
    public async Task VersionDocument_PassesThroughAnUpstreamMirrorsHashesWhenNothingIsCached()
    {
        // Nothing cached locally, so the only hash available is the one the master published.
        // Dropping it would break verification for a node chained below this one.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        string sha = new('b', 64);
        _http.Route(
            $"{MasterBase}/{Provider}/{Version}.json",
            MirrorVersionDocument(hashes: $"zh:{sha}"));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var hashes = archives.GetProperty("linux_amd64").GetProperty("hashes");
        Assert.Equal($"zh:{sha}", Assert.Single(hashes.EnumerateArray()).GetString());
    }

    [Fact]
    public async Task VersionDocument_PublishesTheRegistrysShasumForAnArchiveNotYetCached()
    {
        // The registry protocol's versions list — what a cold master's version document was built
        // from — carries no hash at all; the shasum lives only in the per-platform download
        // document. A cold master (nothing of this archive cached) must still fetch that shasum
        // and publish it as zh:, or a downstream edge chained through it has nothing to verify
        // fetched bytes against.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryVersionsList();
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""
                {"download_url":"{{ReleaseHost}}/acme/internal_{{Version}}_{{Platform}}.zip",
                 "shasum":"{{ArchiveShasum}}"}
                """));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var hashes = archives.GetProperty(Platform).GetProperty("hashes");
        Assert.Equal($"zh:{ArchiveShasum}", Assert.Single(hashes.EnumerateArray()).GetString());
    }

    [Fact]
    public async Task VersionDocument_DoesNotFabricateAHashWhenTheRegistryPublishesNone()
    {
        // The adversarial twin of the above, and the crux of the fix: a master that genuinely
        // cannot obtain a hash for a platform (the registry's download document carries no shasum
        // field at all — a real, if unusual, upstream shape) must keep serving no hashes for it
        // rather than invent one. A fabricated digest would be strictly worse than the pre-existing
        // trust-on-first-use, because a downstream edge treats zh: as verified truth.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryVersionsList();
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{ReleaseHost}}/acme/internal_{{Version}}_{{Platform}}.zip"}"""));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var platform = archives.GetProperty(Platform);
        Assert.False(platform.TryGetProperty("hashes", out _));
        Assert.Equal($"{Version}/{Platform}.zip", platform.GetProperty("url").GetString());
    }

    [Fact]
    public async Task VersionDocument_OmitsAPlatformWhoseShasumFetchFails_RatherThanPublishingItWithNoHash()
    {
        // The security-critical adversarial twin of VersionDocument_DoesNotFabricateAHashWhenThe
        // RegistryPublishesNone: a REGISTRY OUTAGE, not a legitimate "no shasum" answer. Collapsing
        // a fetch failure into the same "no hashes" shape would let a busy or unreachable registry
        // silently reopen trust-on-first-use for a downstream edge, precisely when the upstream is
        // least healthy. The failing platform must be dropped from the document entirely, and a
        // healthy sibling platform in the same document must be unaffected.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/versions",
            Json($$"""
                {"versions":[{"version":"{{Version}}","platforms":[
                    {"os":"linux","arch":"amd64"},{"os":"darwin","arch":"arm64"}]}]}
                """));
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            () => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/darwin/arm64",
            Json($$"""
                {"download_url":"{{ReleaseHost}}/acme/internal_{{Version}}_darwin_arm64.zip",
                 "shasum":"{{ArchiveShasum}}"}
                """));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        Assert.False(archives.TryGetProperty(Platform, out _));
        var darwinHashes = archives.GetProperty("darwin_arm64").GetProperty("hashes");
        Assert.Equal($"zh:{ArchiveShasum}", Assert.Single(darwinHashes.EnumerateArray()).GetString());
    }

    [Fact]
    public async Task VersionDocument_DoesNotRefetchTheRegistrysShasumForAPlatformAlreadyCached()
    {
        // A platform this instance already holds a verified hash for never needs the registry's
        // shasum — ServeVersionDocumentAsync prefers the cached hash over whatever the registry
        // fetch would return, so making that call anyway would be a wasted upstream round trip on
        // every version-document view. The registry's shasum here deliberately differs from the
        // cached hash, so a wrongly-preferred value would be caught by the assertion, not just the
        // unmade request.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryVersionsList();
        string registryShasum = new('e', 64);
        string downloadUrl = $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64";
        _http.Route(downloadUrl, Json($$"""
            {"download_url":"{{ReleaseHost}}/acme/internal_{{Version}}_{{Platform}}.zip",
             "shasum":"{{registryShasum}}"}
            """));
        string cachedSha = new('c', 64);
        await SeedCachedArchiveAsync(cachedSha);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var hashes = archives.GetProperty(Platform).GetProperty("hashes");
        Assert.Equal($"zh:{cachedSha}", Assert.Single(hashes.EnumerateArray()).GetString());
        Assert.DoesNotContain(_http.Urls, u => u == downloadUrl);
    }

    [Fact]
    public async Task ChainedEdge_RejectsATamperedArchive_WhenTheColdMastersVersionDocumentCarriesTheRegistrysShasum()
    {
        // The full loop the defect broke: a cold master (nothing of this archive cached) talking a
        // registry-protocol upstream must still publish a zh: hash sourced from the registry's
        // shasum, and a downstream edge chained to that master must use the hash to catch
        // tampering. Before the fix the master's registry-protocol branch hardcoded
        // UpstreamHashes: null, so the document captured from a real master invocation below
        // carried no hashes entry, and the edge had nothing to verify fetched bytes against — it
        // would trust-on-first-use the tampered bytes and answer 200, not 502.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryVersionsList();
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""
                {"download_url":"{{ReleaseHost}}/acme/internal_{{Version}}_{{Platform}}.zip",
                 "shasum":"{{ArchiveShasum}}"}
                """));

        var masterResult = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);
        var masterContent = Assert.IsType<ContentResult>(masterResult);
        var masterHashes = ArchivesOf(masterContent).GetProperty(Platform).GetProperty("hashes");
        Assert.Equal($"zh:{ArchiveShasum}", Assert.Single(masterHashes.EnumerateArray()).GetString());

        // Chain a downstream edge to exactly that captured document — not a reconstructed one —
        // and hand it bytes that do not match the shasum it advertises.
        await ReplaceUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route($"{MasterBase}/{Provider}/{Version}.json", () => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(masterContent.Content!, Encoding.UTF8, "application/json"),
        });
        _http.Route(
            $"{MasterBase}/{Provider}/{Version}/{Platform}.zip",
            Bytes(Encoding.UTF8.GetBytes("tampered-bytes-that-do-not-match-the-shasum")));

        var edgeResult = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.Equal(StatusCodes.Status502BadGateway, Assert.IsType<ObjectResult>(edgeResult).StatusCode);
    }

    private void RouteRegistryVersionsList() => _http.Route(
        $"{RegistryBase}/v1/providers/acme/internal/versions",
        Json($$"""{"versions":[{"version":"{{Version}}","platforms":[{"os":"linux","arch":"amd64"}]}]}"""));

    // ── Case canonicalization ────────────────────────────────────────────────

    [Fact]
    public async Task MixedCaseSourceAddress_ResolvesToTheCanonicalCoordinate()
    {
        // Terraform matches source addresses case-insensitively. Two spellings resolving to two
        // cache rows would mean an operator's block on one silently not applying to the other.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route(
            $"{MasterBase}/{Provider}/{Version}.json",
            MirrorVersionDocument(hashes: null));
        _http.Route($"{MasterBase}/{Provider}/{Version}/linux_amd64.zip",
            Bytes(Encoding.UTF8.GetBytes("provider-archive-bytes")));

        var result = await BuildController()
            .HandleMirrorRequest($"TF.Example.TEST/ACME/Internal/{Version}/{Platform}.zip", default);

        Assert.IsType<FileStreamResult>(result);

        // The upstream was asked for the canonical spelling, and the cache row landed on the
        // canonical coordinate — the same one the lowercase request would have produced.
        Assert.Contains(
            _http.Urls, u => u == $"{MasterBase}/{Provider}/{Version}/linux_amd64.zip");
        await using var conn = await _db.OpenAsync();
        string? name = await conn.ExecuteScalarAsync<string?>(
            "SELECT name FROM cache_artifact WHERE ecosystem = 'terraform' AND version = @version",
            new { version = Version });
        Assert.Equal(Provider, name);
    }

    // ── Cache-hit accounting ─────────────────────────────────────────────────

    [Fact]
    public async Task CacheHit_RecordsTheAccess()
    {
        // download_count, last_accessed_at (which drives LRU eviction, so a hot provider that only
        // ever hits looks cold), and the "which tenants hold this" vulnerability-response query all
        // read this row.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SeedCachedArchiveAsync(new string('c', 64));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        await using var conn = await _db.OpenAsync();
        long downloads = await conn.ExecuteScalarAsync<long>(
            """
            SELECT taa.download_count
            FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'terraform'
            """,
            new { orgId = _orgId });
        Assert.Equal(1, downloads);

        // No upstream request was made — this is a hit, and the tick must not have cost a fetch.
        Assert.Empty(_http.Urls);
    }

    // ── Reserved namespaces ──────────────────────────────────────────────────

    [Theory]
    [InlineData("index.json")]
    [InlineData("1.2.3.json")]
    public async Task ReservedSourceAddress_IsNeverForwardedUpstream(string document)
    {
        // local_only semantics: a reserved private source address must not be handed to a public
        // registry to answer, which would both disclose the name and serve that registry's version
        // list for it. Terraform is proxy-only, so there is nothing local to fall back to.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SeedReservedNamespaceAsync(Provider);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{document}", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.Empty(_http.Urls);
    }

    // ── Refusal discards the staged blob (no permanent bypass) ───────────────

    [Fact]
    public async Task BlockedFetch_DiscardsTheStagedBlob_SoAReplayReFetchesInsteadOfServingUngated()
    {
        // A source-pin (like every first-fetch gate) refuses BEFORE a cache_artifact row is written,
        // and the Terraform cache-hit lookup probes the blob store by coordinate while its hit gate
        // allows a hit it has no row for. A staged-but-unrecorded blob would therefore answer every
        // later request ungated — a permanent bypass. The fetch must discard the blob on refusal.
        var pinConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_SOURCE_PINNING"] = "true" })
            .Build();
        await new SourcePinRepository(_db, pinConfig)
            .PinIfAbsentAsync(_orgId, "terraform", Provider, "https://previously.example.test", default);

        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route($"{MasterBase}/{Provider}/{Version}.json", MirrorVersionDocument(hashes: null));
        _http.Route($"{MasterBase}/{Provider}/{Version}/linux_amd64.zip",
            Bytes(Encoding.UTF8.GetBytes("pin-violating-bytes")));

        var first = await BuildController(sourcePinning: true).HandleMirrorRequest(ArchivePath, default);
        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<StatusCodeResult>(first).StatusCode);

        // The blob was discarded, so a replay cannot be answered from cache: still 403, never a
        // 200 HIT of the ungated bytes.
        string blobKey = BlobKeys.Terraform(_orgId, "tf.example.test", "acme", "internal", Version, Platform);
        Assert.Null(await _blobs.GetAsync(blobKey, default));

        var second = await BuildController(sourcePinning: true).HandleMirrorRequest(ArchivePath, default);
        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<StatusCodeResult>(second).StatusCode);
    }

    [Fact]
    public async Task RegistryFetch_WithNoShasumOnAForeignArchiveHost_Refuses()
    {
        // The registry protocol's shasum is the only thing binding third-party release-host bytes to
        // the registry that vouched for them. No shasum on a foreign host leaves nothing to verify —
        // refuse rather than store trust-on-first-use bytes from a host the operator never configured.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{downloadUrl}}"}"""));
        _http.Route(downloadUrl, Bytes(Encoding.UTF8.GetBytes("unverifiable-bytes")));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.Equal(StatusCodes.Status502BadGateway, Assert.IsType<ObjectResult>(result).StatusCode);
        // The foreign archive host was never contacted — refused before the fetch.
        Assert.DoesNotContain(_http.Urls, u => u == downloadUrl);
    }

    [Fact]
    public async Task ArchiveChecksumMismatch_Answers502_NotAnUnhandled500()
    {
        // A checksum mismatch is the most security-significant outcome on the fetch path. It must
        // map to a well-formed 502 like every peer proxy, not escape as an opaque 500.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{downloadUrl}}","shasum":"{{new string('0', 64)}}"}"""));
        _http.Route(downloadUrl, Bytes(Encoding.UTF8.GetBytes("bytes-that-do-not-match-the-shasum")));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.Equal(StatusCodes.Status502BadGateway, Assert.IsType<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task ArchivePathWithEmptyArch_Is404_WithoutContactingUpstream()
    {
        // "linux_.zip" passes a bare Contains('_') check and would compose a malformed
        // /download/linux/ upstream URL. It must be rejected at parse time, before any fetch.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}/linux_.zip", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.Empty(_http.Urls);
    }

    [Fact]
    public async Task VersionDocument_SuppressesTheZipHashOfARowFetchedByAnotherTenant()
    {
        // cache_artifact is a global plane: its content_hash belongs to whichever tenant fetched the
        // coordinate first. Publishing a foreign tenant's hash as this org's zh: would let one tenant
        // dictate the integrity anchor another advertises, breaking a downstream edge that takes zh:
        // as its only fetch-time checksum. Emit only when the row's blob_key is this org's own.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        _http.Route($"{MasterBase}/{Provider}/{Version}.json", MirrorVersionDocument(hashes: null));

        string foreignBlobKey = BlobKeys.Terraform(
            "another-tenant", "tf.example.test", "acme", "internal", Version, Platform);
        await SeedCachedArchiveWithBlobKeyAsync(new string('d', 64), foreignBlobKey);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        Assert.False(archives.GetProperty("linux_amd64").TryGetProperty("hashes", out _));
    }

    // ── Offline / cache-only metadata serving ────────────────────────────────

    [Fact]
    public async Task VersionIndex_ServesCachedVersionsWhenPassthroughIsOff_WithoutContactingUpstream()
    {
        // Proxying disabled is documented as "only packages already cached are served". The metadata
        // documents must honour that too, or a fully-cached provider is undiscoverable and init fails
        // on the discovery step before it can reach the cached archive.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SeedCachedArchiveAsync(new string('c', 64));
        await SetPassthroughAsync(enabled: false);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        var versions = JsonDocument.Parse(Assert.IsType<ContentResult>(result).Content!)
            .RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty(Version, out _));
        Assert.Empty(_http.Urls);
    }

    [Fact]
    public async Task VersionIndex_ServesCachedVersionsWhenUpstreamIsUnavailable()
    {
        // Egress to the registry is blocked (the ADR's motivating case). A cached provider must stay
        // resolvable rather than 503-ing the whole init.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SeedCachedArchiveAsync(new string('c', 64));
        _http.Route($"{MasterBase}/{Provider}/index.json",
            () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        var versions = JsonDocument.Parse(Assert.IsType<ContentResult>(result).Content!)
            .RootElement.GetProperty("versions");
        Assert.True(versions.TryGetProperty(Version, out _));
    }

    [Fact]
    public async Task VersionDocument_ServesCachedArchivesWithTheirZipHashWhenPassthroughIsOff()
    {
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        string sha = new('c', 64);
        await SeedCachedArchiveAsync(sha);
        await SetPassthroughAsync(enabled: false);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/{Version}.json", default);

        var archives = ArchivesOf(Assert.IsType<ContentResult>(result));
        var platform = archives.GetProperty(Platform);
        Assert.Equal($"{Version}/{Platform}.zip", platform.GetProperty("url").GetString());
        Assert.Equal($"zh:{sha}", Assert.Single(platform.GetProperty("hashes").EnumerateArray()).GetString());
        Assert.Empty(_http.Urls);
    }

    [Fact]
    public async Task VersionIndex_404sForAnUnknownProviderWhenNothingIsCached()
    {
        // The fallback must not turn an unresolvable provider into an empty 200 — that would make
        // every unknown provider look mirrored. Nothing cached, proxying off ⇒ 404.
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SetPassthroughAsync(enabled: false);

        var result = await BuildController().HandleMirrorRequest($"{Provider}/index.json", default);

        Assert.IsType<NotFoundResult>(result);
    }

    // ── Release-age cooldown (min_release_age_hours) ─────────────────────────

    [Fact]
    public async Task RecentlyPublishedProvider_IsBlockedByTheReleaseAgeCooldown()
    {
        // With no OSV feed for terraform, the release-age hold is close to the only proactive gate
        // that can work — and it can only fire if the upstream publish timestamp is captured. A
        // version published 1h ago against a 72h hold must be refused on the first fetch, before any
        // byte reaches the client.
        var clock = TestTime.Frozen();
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        await SetMinReleaseAgeAsync(72);
        RouteRegistryArchive(publishedAt: clock.GetUtcNow().AddHours(-1).ToUtcIso());

        var result = await BuildController(clock: clock).HandleMirrorRequest(ArchivePath, default);

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<StatusCodeResult>(result).StatusCode);
    }

    [Fact]
    public async Task ProviderOlderThanTheCooldownWindow_IsServed()
    {
        // The adversarial twin: the gate keys on age, not a blanket block. A version published 100h
        // ago clears the same 72h hold and serves — proving the block above is the cooldown firing,
        // not the capture breaking every fetch.
        var clock = TestTime.Frozen();
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        await SetMinReleaseAgeAsync(72);
        RouteRegistryArchive(publishedAt: clock.GetUtcNow().AddHours(-100).ToUtcIso());

        var result = await BuildController(clock: clock).HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
    }

    [Fact]
    public async Task ChainedMirrorWithNoTimestamp_FailsOpenOnTheCooldown()
    {
        // The network mirror protocol carries no publish timestamp, so a chained edge cannot capture
        // one. The cooldown fails open there rather than blocking every provider — correct, because
        // the master enforces its own cooldown on the real upstream fetch.
        var clock = TestTime.Frozen();
        await SeedUpstreamAsync(MasterBase, mirror: true, secret: null);
        await SetMinReleaseAgeAsync(72);
        _http.Route($"{MasterBase}/{Provider}/{Version}.json", MirrorVersionDocument(hashes: null));
        _http.Route($"{MasterBase}/{Provider}/{Version}/linux_amd64.zip",
            Bytes(Encoding.UTF8.GetBytes("provider-archive-bytes")));

        var result = await BuildController(clock: clock).HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        // The mirror was never asked for a per-version registry-metadata document: that endpoint is
        // registry-protocol only (`/v1/providers/{ns}/{type}/{version}`). Asserting on that shape —
        // not the mirror's own path — is what catches the regression where the IsMirror guard is
        // removed and a registry-style metadata GET leaks onto the mirror fetch path.
        Assert.DoesNotContain(_http.Urls, u => u.Contains("/v1/providers/", StringComparison.Ordinal));
    }

    // ── Fixtures ─────────────────────────────────────────────────────────────

    private static string ArchivePath => $"{Provider}/{Version}/{Platform}.zip";

    private async Task SetPassthroughAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId = _orgId });
    }

    private async Task SetMinReleaseAgeAsync(int hours)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET min_release_age_hours = @h WHERE org_id = @orgId",
            new { h = hours, orgId = _orgId });
    }

    /// <summary>
    /// Routes the three registry-protocol endpoints an archive fetch touches: the per-platform
    /// download document (with a matching shasum), the per-version metadata document carrying
    /// <paramref name="publishedAt"/>, and the archive bytes on the discovered release host.
    /// </summary>
    private void RouteRegistryArchive(string publishedAt)
    {
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""{"download_url":"{{downloadUrl}}","shasum":"{{ArchiveShasum}}"}"""));
        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}",
            Json($$"""{"published_at":"{{publishedAt}}"}"""));
        _http.Route(downloadUrl, Bytes(Encoding.UTF8.GetBytes("provider-archive-bytes")));
    }

    private static JsonElement ArchivesOf(ContentResult content) =>
        JsonDocument.Parse(content.Content!).RootElement.GetProperty("archives");

    /// <summary>
    /// A mirror-protocol version document advertising the one platform under test, optionally
    /// carrying the hash entry a mirror publishes for it.
    /// </summary>
    private static Func<HttpResponseMessage> MirrorVersionDocument(string? hashes)
    {
        string hashField = hashes is null ? "" : $$""","hashes":["{{hashes}}"]""";
        return Json(
            $$"""{"archives":{"{{Platform}}":{"url":"{{Version}}/{{Platform}}.zip"{{hashField}}""" + "}}}");
    }

    private static Func<HttpResponseMessage> Json(string body) => () => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    private static Func<HttpResponseMessage> Bytes(byte[] body) => () => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new ByteArrayContent(body),
    };

    private async Task SeedUpstreamAsync(string url, bool mirror, string? secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry
                (id, org_id, ecosystem, url, position, auth_type, secret, upstream_protocol)
            VALUES (@id, @orgId, 'terraform', @url, 0, @authType, @secret, @protocol)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = _orgId,
                url,
                authType = secret is null ? "anonymous" : "bearer",
                secret,
                protocol = mirror ? UpstreamRegistryRepository.MirrorProtocol : null,
            });
    }

    /// <summary>
    /// Swaps this org's terraform upstream row for a different one — used to move the same test
    /// org from acting as a chained edge's downstream master to acting as the edge itself, without
    /// two upstream_registry rows racing for priority.
    /// </summary>
    private async Task ReplaceUpstreamAsync(string url, bool mirror, string? secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'terraform'",
            new { orgId = _orgId });
        await SeedUpstreamAsync(url, mirror, secret);
    }

    private async Task SeedReservedNamespaceAsync(string pattern)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO reserved_namespace (id, org_id, ecosystem, pattern, created_at)
            VALUES (@id, @orgId, 'terraform', @pattern, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = _orgId,
                pattern,
                now = TestTime.Frozen().GetUtcNow().ToUtcIso(),
            });
    }

    /// <summary>
    /// Puts one provider archive in the blob store and on the cache plane, as a completed first
    /// fetch would have left it.
    /// </summary>
    private async Task SeedCachedArchiveAsync(string sha256)
    {
        string blobKey = BlobKeys.Terraform(_orgId, RegistryHost, "acme", "internal", Version, Platform);
        await _blobs.PutAsync(blobKey, new MemoryStream(Encoding.UTF8.GetBytes("cached-archive")), default);

        var cacheArtifacts = new CacheArtifactRepository(_db);
        var recorder = new CacheAccessRecorder(
            cacheArtifacts, new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        await recorder.RecordAccessAsync(
            new CacheAccess(_orgId, "terraform", Provider, Version, $"{Platform}.zip",
                sha256, SizeBytes: 14, blobKey, UpstreamUrl: null, Origin: CacheAccessOrigin.FirstFetch), default);
    }

    /// <summary>
    /// Records a cache-plane row for this org's coordinate whose <c>blob_key</c> is an arbitrary
    /// (e.g. another tenant's) key — as the global plane would leave it when a different tenant
    /// fetched the coordinate first. No blob is stored; the version-document path reads the row's
    /// hash, not the bytes.
    /// </summary>
    private async Task SeedCachedArchiveWithBlobKeyAsync(string sha256, string blobKey)
    {
        var cacheArtifacts = new CacheArtifactRepository(_db);
        var recorder = new CacheAccessRecorder(
            cacheArtifacts, new TenantArtifactAccessRepository(_db),
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        await recorder.RecordAccessAsync(
            new CacheAccess(_orgId, "terraform", Provider, Version, $"{Platform}.zip",
                sha256, SizeBytes: 14, blobKey, UpstreamUrl: null, Origin: CacheAccessOrigin.FirstFetch), default);
    }

    // ── Terraform signature verification (provenance) ────────────────────────

    [Fact]
    public async Task ValidShasumsSignature_UnderTrustedAnchor_Verifies_AndServes()
    {
        var (secretKey, publicKey) = GenerateTerraformKeyPair();
        SeedTerraformAnchor(publicKey);
        await SetVerifyTerraformSignaturesAsync("block");

        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        byte[] archiveBytes = Encoding.UTF8.GetBytes("provider-archive-bytes");
        string shasumFilename = $"terraform-provider-internal_{Version}_{Platform}.zip";
        byte[] shasums = Shasums((ArchiveShasum, shasumFilename));
        byte[] shasumsSig = SignDetachedTerraform(shasums, secretKey);
        string shasumsUrl = $"{RegistryBase}/shasums/{Version}/SHA256SUMS";
        string shasumsSigUrl = $"{RegistryBase}/shasums/{Version}/SHA256SUMS.sig";

        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""
                {"download_url":"{{downloadUrl}}","shasum":"{{ArchiveShasum}}",
                 "filename":"{{shasumFilename}}",
                 "shasums_url":"{{shasumsUrl}}","shasums_signature_url":"{{shasumsSigUrl}}"}
                """));
        _http.Route(downloadUrl, Bytes(archiveBytes));
        _http.Route(shasumsUrl, Bytes(shasums));
        _http.Route(shasumsSigUrl, Bytes(shasumsSig));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Equal("verified", await ReadProvenanceStatusAsync());
    }

    [Fact]
    public async Task BadShasumsSignature_UnderBlockMode_IsRefused()
    {
        var (secretKey, _) = GenerateTerraformKeyPair();
        // Pin a DIFFERENT key than the one that actually signs the SHASUMS below.
        var (_, differentPublicKey) = GenerateTerraformKeyPair();
        SeedTerraformAnchor(differentPublicKey);
        await SetVerifyTerraformSignaturesAsync("block");

        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        string downloadUrl = $"{ReleaseHost}/acme/internal_{Version}_{Platform}.zip";
        byte[] archiveBytes = Encoding.UTF8.GetBytes("provider-archive-bytes");
        string shasumFilename = $"terraform-provider-internal_{Version}_{Platform}.zip";
        byte[] shasums = Shasums((ArchiveShasum, shasumFilename));
        byte[] shasumsSig = SignDetachedTerraform(shasums, secretKey);
        string shasumsUrl = $"{RegistryBase}/shasums/{Version}/SHA256SUMS";
        string shasumsSigUrl = $"{RegistryBase}/shasums/{Version}/SHA256SUMS.sig";

        _http.Route(
            $"{RegistryBase}/v1/providers/acme/internal/{Version}/download/linux/amd64",
            Json($$"""
                {"download_url":"{{downloadUrl}}","shasum":"{{ArchiveShasum}}",
                 "filename":"{{shasumFilename}}",
                 "shasums_url":"{{shasumsUrl}}","shasums_signature_url":"{{shasumsSigUrl}}"}
                """));
        _http.Route(downloadUrl, Bytes(archiveBytes));
        _http.Route(shasumsUrl, Bytes(shasums));
        _http.Route(shasumsSigUrl, Bytes(shasumsSig));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task AbsentShasumsSidecar_UnderBlockMode_IsRefused()
    {
        // A trust anchor IS configured, but the registry publishes no shasums_url/
        // shasums_signature_url for this download — Unsigned under a 'block' policy.
        var (_, publicKey) = GenerateTerraformKeyPair();
        SeedTerraformAnchor(publicKey);
        await SetVerifyTerraformSignaturesAsync("block");

        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryArchive(TestTime.KnownNow.ToString("O"));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task BlockMode_WithNoTrustAnchorConfigured_DeniesEveryArchive()
    {
        // Fail-closed: 'block' with an empty anchor set must deny rather than silently pass —
        // no SeedTerraformAnchor call at all, mirroring the RPM/Maven unbacked-enforcement posture.
        await SetVerifyTerraformSignaturesAsync("block");

        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryArchive(TestTime.KnownNow.ToString("O"));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(StatusCodes.Status403Forbidden, status.StatusCode);
    }

    [Fact]
    public async Task OffMode_Default_IsUnaffectedByAMissingSignatureChain()
    {
        // Default posture: verify_terraform_signatures is 'off' and no anchor is configured. A
        // registry that publishes no shasums_url/shasums_signature_url — the common case today —
        // must not affect serving.
        await SeedUpstreamAsync(RegistryBase, mirror: false, secret: null);
        RouteRegistryArchive(TestTime.KnownNow.ToString("O"));

        var result = await BuildController().HandleMirrorRequest(ArchivePath, default);

        Assert.IsType<FileStreamResult>(result);
        Assert.Null(await ReadProvenanceStatusAsync());
    }

    private async Task SetVerifyTerraformSignaturesAsync(string mode)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET verify_terraform_signatures = @mode WHERE org_id = @orgId",
            new { mode, orgId = _orgId });
    }

    private async Task<string?> ReadProvenanceStatusAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT provenance_status FROM cache_artifact WHERE ecosystem = 'terraform' AND version = @version",
            new { version = Version });
    }

    // Builds a sha256sum(1)-style SHASUMS text: "<64-hex hash>  <filename>" per line.
    private static byte[] Shasums(params (string Sha256, string Filename)[] entries)
    {
        var sb = new StringBuilder();
        foreach (var (sha256, filename) in entries)
        {
            sb.Append(sha256).Append("  ").Append(filename).Append('\n');
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // Generates an RSA-2048 keypair as a BouncyCastle PGP key pair, mirroring
    // TerraformProvenanceVerifierTests's helper.
    private static (Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey SecretKey, Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKey PublicKey)
        GenerateTerraformKeyPair()
    {
        var gen = Org.BouncyCastle.Security.GeneratorUtilities.GetKeyPairGenerator("RSA");
        gen.Init(new Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new Org.BouncyCastle.Security.SecureRandom(), 2048, 12));
        var kp = gen.GenerateKeyPair();

        var pgpPair = new Org.BouncyCastle.Bcpg.OpenPgp.PgpKeyPair(
            Org.BouncyCastle.Bcpg.PublicKeyAlgorithmTag.RsaGeneral, kp,
            new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var secretKey = new Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey(
            Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.DefaultCertification,
            pgpPair,
            "test-terraform-signer@example.com",
            Org.BouncyCastle.Bcpg.SymmetricKeyAlgorithmTag.Null,
            passPhrase: null,
            useSha1: true,
            null, null,
            new Org.BouncyCastle.Security.SecureRandom());

        return (secretKey, secretKey.PublicKey);
    }

    // Produces a detached, non-armored (binary) OpenPGP signature over the given bytes.
    private static byte[] SignDetachedTerraform(byte[] data, Org.BouncyCastle.Bcpg.OpenPgp.PgpSecretKey secretKey)
    {
        var privateKey = secretKey.ExtractPrivateKey(passPhrase: null);
        var sigGen = new Org.BouncyCastle.Bcpg.OpenPgp.PgpSignatureGenerator(
            secretKey.PublicKey.Algorithm, Org.BouncyCastle.Bcpg.HashAlgorithmTag.Sha256);
        sigGen.InitSign(Org.BouncyCastle.Bcpg.OpenPgp.PgpSignature.BinaryDocument, privateKey);
        sigGen.Update(data);

        using var ms = new MemoryStream();
        var sig = sigGen.Generate();
        sig.Encode(ms);
        return ms.ToArray();
    }

    private void SeedTerraformAnchor(Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKey publicKey)
    {
        using var armorMs = new MemoryStream();
        using (var armoredOut = new Org.BouncyCastle.Bcpg.ArmoredOutputStream(armorMs))
        {
            publicKey.Encode(armoredOut);
        }

        string material = Encoding.ASCII.GetString(armorMs.ToArray());
        string fingerprint = Convert.ToHexString(publicKey.GetFingerprint()).ToLowerInvariant();
        _trustStore.AddAnchor(_orgId, "terraform", new TrustAnchorMaterial
        {
            Id = Guid.NewGuid().ToString("N"),
            AnchorKind = "pgp",
            Material = material,
            KeyId = fingerprint,
        });
    }

    // ── Controller construction ──────────────────────────────────────────────

    private TerraformController BuildController(
        bool sourcePinning = false, bool airGapped = false, TimeProvider? clock = null)
    {
        var time = clock ?? TimeProvider.System;
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("tf-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "tf-proxy-org");
        http.User = new ClaimsPrincipal(new ClaimsIdentity());

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(
                    Path.GetTempPath(), $"dependably-tf-proxy-{Guid.NewGuid():N}"),
            })
            .Build();

        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var audit = new AuditRepository(_db);
        var upstream = new UpstreamClient(
            new StaticHttpClientFactory(new HttpClient(_http)), tiered, audit,
            new AllowAllValidator(), new StubAirGap(airGapped), new UnlimitedDisk(),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);

        var cacheArtifacts = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(
            cacheArtifacts, tenantAccess, NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        var packages = new PackageRepository(_db);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var proxyVersions = new ProxyVersionRecorder(
            packages, audit, licenses, cacheArtifacts,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, TestOsvSource.Create(), vulns, audit, config, new StubAirGap(Enabled: false),
            NullLogger<VulnerabilityScanService>.Instance, TimeProvider.System,
            new OrgRepository(_db), Substitute.For<IPackageEventSink>(),
            new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, TimeProvider.System)));

        var pinConfig = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_SOURCE_PINNING"] = sourcePinning ? "true" : "false",
            })
            .Build();

        var svc = new TerraformControllerServices(
            Tokens: new TokenRepository(_db, TimeProvider.System),
            Orgs: new OrgRepository(_db),
            Blobs: tiered.Cache,
            Upstream: upstream,
            Registries: new UpstreamRegistryResolver(
                new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured())),
            CacheRecorder: cacheRecorder,
            CacheArtifacts: cacheArtifacts,
            TenantAccess: tenantAccess,
            Reserved: new ReservedNamespaceService(
                _db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System),
            BlockGate: TestBlockGate.Create(_db, time, _trustStore),
            ProxyFetch: new ProxyFetchService(
                cacheRecorder, proxyVersions, cacheArtifacts, tenantAccess, scanner,
                TestBlockGate.Create(_db, time, _trustStore), audit, time,
                new SourcePinRepository(_db, pinConfig)),
            Time: time,
            Logger: NullLogger<TerraformController>.Instance,
            TerraformProvenance: new Dependably.Protocol.Provenance.TerraformProvenanceVerifier(
                _trustStore,
                NullLogger<Dependably.Protocol.Provenance.TerraformProvenanceVerifier>.Instance));

        return new TerraformController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    /// <summary>
    /// Serves canned responses keyed by absolute URL and records every request with the
    /// <c>Authorization</c> header it carried. Keying on the full URL — rather than proxying
    /// everything at one mock server — is what lets these tests tell "the request to the configured
    /// upstream" apart from "the request to the host that upstream named".
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);
        private readonly List<(string Url, string? Authorization)> _requests = [];

        public void Route(string url, Func<HttpResponseMessage> response) => _routes[url] = response;

        public IReadOnlyList<string> Urls
        {
            get
            {
                lock (_gate)
                {
                    return _requests.Select(r => r.Url).ToList();
                }
            }
        }

        public string? AuthorizationFor(string url)
        {
            lock (_gate)
            {
                var match = _requests.FindAll(r => r.Url == url);
                Assert.NotEmpty(match);
                return match[0].Authorization;
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            string? authorization = request.Headers.TryGetValues("Authorization", out var values)
                ? string.Join(",", values)
                : null;

            lock (_gate)
            {
                _requests.Add((url, authorization));
            }

            return Task.FromResult(_routes.TryGetValue(url, out var response)
                ? response()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>The staging floor is not what these tests exercise; a real temp volume that
    /// happens to sit below it would fail every fetch for an unrelated reason.</summary>
    private sealed class UnlimitedDisk : IStagingDiskInfo
    {
        public long GetAvailableBytes() => long.MaxValue;
        public long GetTotalBytes() => long.MaxValue;
        public long GetStagingDirectoryUsedBytes() => 0;
    }

    private sealed record StubAirGap(bool Enabled) : IAirGapMode
    {
        public bool IsEnabled => Enabled;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }
}
