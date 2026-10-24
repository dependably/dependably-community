using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Reserved namespaces keep a name off every upstream registry for npm, PyPI, NuGet, Cargo, Hex
/// and Go on the server-side paths that look a package up by name: the upstream-latest resolve
/// (and so the first-fetch seed in <see cref="ProxyVersionRecorder"/>) and
/// <see cref="PackageLookupService"/>, including their secondary fetches (the NuGet registration
/// leaf, the crates.io API leg). Every outbound request goes through a recording handler, which is
/// the evidence: a reserved name makes zero requests, while a name that only shares the reserved
/// prefix without its boundary, or the same name in an org without the reservation, still reaches
/// upstream exactly once.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamReservationAcrossEcosystemsTests : IAsyncLifetime, IDisposable
{
    private const string UpstreamUrl = "http://upstream.test";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly RSA _hexKey = RSA.Create(2048);
    private ReservedNamespaceService _reserved = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _reserved = new ReservedNamespaceService(_db, new MemoryCache(new MemoryCacheOptions()), TimeProvider.System);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    public void Dispose() => _hexKey.Dispose();

    /// <summary>
    /// Ecosystem, reserved pattern, a name the pattern covers (in the form a client or a stored
    /// purl name spells it), and an adversarial twin the pattern must not cover.
    /// </summary>
    public static TheoryData<string, string, string, string> Cases() => new()
    {
        { "npm", "@acme/*", "@acme/internal-tool", "@acmecorp/x" },
        { "pypi", "acme-*", "Acme_Internal", "acmecorp-tool" },
        { "nuget", "Acme.*", "acme.internal.tool", "AcmeCorp.Tool" },
        { "cargo", "acme-*", "acme-internal", "acmecorp" },
        { "hex", "acme_*", "acme_internal", "acmecorp" },
        { "golang", "github.com/acme", "github.com/acme/internal", "github.com/acmecorp/tool" },
    };

    // ── Upstream-latest resolve ─────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Resolver_ReservedName_MakesNoRequest_AndReturnsReserved(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = twin;
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var latest = await BuildResolver(handler).ResolveAsync(ecosystem, orgId, reservedName);

        Assert.True(latest.IsReserved);
        Assert.NotSame(UpstreamLatestVersion.None, latest);
        Assert.Null(latest.Version);
        Assert.Null(latest.StableVersionsDescending);
        Assert.Empty(handler.Urls);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Resolver_PrefixTwin_ReachesUpstreamOnce(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = reservedName;
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var latest = await BuildResolver(handler).ResolveAsync(ecosystem, orgId, twin);

        Assert.False(latest.IsReserved);
        Assert.Single(handler.Urls);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Resolver_AnotherOrgsReservation_DoesNotApply(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = twin;
        var handler = new RecordingHandler();
        string reservingOrg = await SeedOrgAsync(ecosystem);
        string otherOrg = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(reservingOrg, ecosystem, pattern, createdBy: null);
        var resolver = BuildResolver(handler);

        var forReserving = await resolver.ResolveAsync(ecosystem, reservingOrg, reservedName);
        Assert.Empty(handler.Urls);

        var forOther = await resolver.ResolveAsync(ecosystem, otherOrg, reservedName);

        Assert.True(forReserving.IsReserved);
        Assert.False(forOther.IsReserved);
        Assert.Single(handler.Urls);
    }

    [Fact]
    public async Task Resolver_NpmPurlNameWithEncodedScope_IsMatchedUnescaped()
    {
        // A cached npm row can carry its scope percent-encoded; the reservation is matched against
        // the same unescaped name the packument URL would be composed from.
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("npm");
        await _reserved.AddAsync(orgId, "npm", "@acme/*", createdBy: null);
        var resolver = BuildResolver(handler);

        var reserved = await resolver.ResolveAsync("npm", orgId, "%40acme%2Finternal-tool");
        Assert.True(reserved.IsReserved);
        Assert.Empty(handler.Urls);

        var twin = await resolver.ResolveAsync("npm", orgId, "%40acmecorp%2Fx");
        Assert.False(twin.IsReserved);
        Assert.Equal($"{UpstreamUrl}/@acmecorp/x", Assert.Single(handler.Urls));
    }

    [Fact]
    public async Task Resolver_NuGet_ReservedName_SkipsTheRegistrationLeafToo()
    {
        // A successful flatcontainer read is followed by a registration-leaf fetch for the
        // publish date. Neither is made for a reserved id; the twin makes both.
        var handler = new RecordingHandler(url => url.Contains("/flatcontainer/", StringComparison.Ordinal)
            ? Json("""{"versions":["1.0.0","2.0.0"]}""")
            : Json("""{"published":"2026-01-02T03:04:05Z"}"""));
        string orgId = await SeedOrgAsync("nuget");
        await _reserved.AddAsync(orgId, "nuget", "Acme.*", createdBy: null);
        var resolver = BuildResolver(handler);

        var reserved = await resolver.ResolveAsync("nuget", orgId, "Acme.Internal");
        Assert.True(reserved.IsReserved);
        Assert.Empty(handler.Urls);

        var twin = await resolver.ResolveAsync("nuget", orgId, "AcmeCorp.Tool");
        Assert.Equal("2.0.0", twin.Version);
        Assert.Equal(
            [
                $"{UpstreamUrl}/flatcontainer/acmecorp.tool/index.json",
                $"{UpstreamUrl}/registration5-gz-semver2/acmecorp.tool/2.0.0.json",
            ],
            handler.Urls);
    }

    // ── First-fetch seed (ProxyVersionRecorder) through the gated resolver ──────

    [Fact]
    public async Task FirstFetchSeed_ReservedNpmName_NoRequest_AndSharedRowLeftAlone()
    {
        // The cache_artifact row is shared across orgs: a seed for the org that reserved the name
        // makes no request, records no upstream baseline, and leaves the row's versions_behind
        // (written for an org that does consult upstream) as it was.
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("npm");
        await _reserved.AddAsync(orgId, "npm", "@acme/*", createdBy: null);
        string caId = await SeedNpmCacheArtifactAsync(orgId, "@acme/internal-tool", "1.0.0", versionsBehind: 3);

        await BuildRecorder(handler).RecordAsync(await BuildNpmRequestAsync(orgId, "@acme/internal-tool", "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Empty(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Null(await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE org_id = @orgId AND purl_name = '@acme/internal-tool'",
            new { orgId }));
        Assert.Equal(3, await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId }));
    }

    [Fact]
    public async Task FirstFetchSeed_PrefixTwin_SeedsFromOneRequest()
    {
        var handler = new RecordingHandler(_ => Json(
            """{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"2.0.0":{}}}"""));
        string orgId = await SeedOrgAsync("npm");
        await _reserved.AddAsync(orgId, "npm", "@acme/*", createdBy: null);
        string caId = await SeedNpmCacheArtifactAsync(orgId, "@acmecorp/x", "1.0.0", versionsBehind: null);

        await BuildRecorder(handler).RecordAsync(await BuildNpmRequestAsync(orgId, "@acmecorp/x", "1.0.0"),
            extractLicenses: null, extractManifest: null, cacheArtifactId: caId);

        Assert.Single(handler.Urls);
        await using var conn = await _db.OpenAsync();
        Assert.Equal("2.0.0", await conn.QuerySingleAsync<string?>(
            "SELECT upstream_latest_version FROM packages WHERE org_id = @orgId AND purl_name = '@acmecorp/x'",
            new { orgId }));
        Assert.Equal(1, await conn.QuerySingleAsync<int?>(
            "SELECT versions_behind FROM cache_artifact WHERE id = @id", new { id = caId }));
    }

    // ── Package lookup ──────────────────────────────────────────────────────────

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Lookup_ReservedName_NoVersion_IsReserved_WithoutAnyRequest(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        // A reservation is a standing operator choice, so it has its own outcome rather than
        // reading as an unreachable upstream.
        _ = twin;
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var outcome = await BuildLookup(handler).LookupAsync(new PackageLookupRequest(orgId, ecosystem, reservedName, null));

        Assert.Equal(PackageLookupStatus.Reserved, outcome.Status);
        Assert.Equal(ecosystem, outcome.Reason);
        Assert.Empty(handler.Urls);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Lookup_ReservedName_ExplicitVersion_AnswersLocally_WithoutAnyRequest(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        // The advisory and licence verdict still run; the upstream-derived checks are reported
        // unavailable and the result says the name is reserved.
        _ = twin;
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var outcome = await BuildLookup(handler).LookupAsync(
            new PackageLookupRequest(orgId, ecosystem, reservedName, "1.0.0"));

        Assert.Equal(PackageLookupStatus.Ok, outcome.Status);
        Assert.Equal("1.0.0", outcome.Result!.Version);
        Assert.True(outcome.Result.Reserved);
        Assert.Contains("release_age", outcome.Result.UnavailableChecks);
        Assert.Contains("license", outcome.Result.UnavailableChecks);
        Assert.Empty(handler.Urls);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Lookup_PrefixTwin_ReachesUpstreamOnce(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = reservedName;
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(orgId, ecosystem, pattern, createdBy: null);

        var outcome = await BuildLookup(handler).LookupAsync(new PackageLookupRequest(orgId, ecosystem, twin, null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
        Assert.Single(handler.Urls);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Lookup_AnotherOrgsReservation_DoesNotApply(
        string ecosystem, string pattern, string reservedName, string twin)
    {
        _ = twin;
        var handler = new RecordingHandler();
        string reservingOrg = await SeedOrgAsync(ecosystem);
        string otherOrg = await SeedOrgAsync(ecosystem);
        await _reserved.AddAsync(reservingOrg, ecosystem, pattern, createdBy: null);
        var lookup = BuildLookup(handler);

        var forReserving = await lookup.LookupAsync(new PackageLookupRequest(reservingOrg, ecosystem, reservedName, null));
        Assert.Empty(handler.Urls);

        var forOther = await lookup.LookupAsync(new PackageLookupRequest(otherOrg, ecosystem, reservedName, null));

        Assert.Equal(PackageLookupStatus.Reserved, forReserving.Status);
        Assert.Equal(PackageLookupStatus.UpstreamNotFound, forOther.Status);
        Assert.Single(handler.Urls);
    }

    [Fact]
    public async Task Lookup_Cargo_ReservedName_SkipsTheCratesIoApiLegToo()
    {
        // With crates.io's own index configured, a found version is followed by a crates.io API
        // read for licence and publish date. Neither request is made for a reserved crate; the
        // twin makes both.
        const string cratesIoIndex = "https://index.crates.io";
        var handler = new RecordingHandler(url => url.StartsWith(cratesIoIndex, StringComparison.Ordinal)
            ? Json("""{"name":"acmecorp","vers":"1.0.0","deps":[],"cksum":"00","features":{},"yanked":false}""")
            : Json("""{"crate":{"id":"acmecorp"},"versions":[{"num":"1.0.0","license":"MIT","created_at":"2026-01-02T03:04:05Z"}]}"""));
        string orgId = await SeedOrgAsync("cargo", cratesIoIndex);
        await _reserved.AddAsync(orgId, "cargo", "acme*", createdBy: null);
        string otherOrg = await SeedOrgAsync("cargo", cratesIoIndex);
        var lookup = BuildLookup(handler);

        var reserved = await lookup.LookupAsync(new PackageLookupRequest(orgId, "cargo", "acmecorp", "1.0.0"));
        Assert.Equal(PackageLookupStatus.Ok, reserved.Status);
        Assert.Empty(handler.Urls);

        var open = await lookup.LookupAsync(new PackageLookupRequest(otherOrg, "cargo", "acmecorp", "1.0.0"));
        Assert.Equal(PackageLookupStatus.Ok, open.Status);
        Assert.Contains(handler.Urls, u => u.StartsWith(cratesIoIndex, StringComparison.Ordinal));
        Assert.Contains("https://crates.io/api/v1/crates/acmecorp", handler.Urls);
    }

    [Fact]
    public async Task Lookup_NuGet_ReservedName_SkipsTheNuspecLicenceLegToo()
    {
        var handler = new RecordingHandler(url => url.EndsWith("/index.json", StringComparison.Ordinal)
            ? Json("""{"versions":["1.0.0"]}""")
            : new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "<package><metadata><license type=\"expression\">MIT</license></metadata></package>",
                    Encoding.UTF8, "application/xml"),
            });
        string orgId = await SeedOrgAsync("nuget");
        await _reserved.AddAsync(orgId, "nuget", "Acme.*", createdBy: null);
        string otherOrg = await SeedOrgAsync("nuget");
        var lookup = BuildLookup(handler);

        var reserved = await lookup.LookupAsync(new PackageLookupRequest(orgId, "nuget", "Acme.Internal", "1.0.0"));
        Assert.Equal(PackageLookupStatus.Ok, reserved.Status);
        Assert.Empty(handler.Urls);

        var open = await lookup.LookupAsync(new PackageLookupRequest(otherOrg, "nuget", "Acme.Internal", "1.0.0"));
        Assert.Equal(PackageLookupStatus.Ok, open.Status);
        Assert.Contains($"{UpstreamUrl}/flatcontainer/acme.internal/1.0.0/acme.internal.nuspec", handler.Urls);
    }

    // ── Go bang-encoding ────────────────────────────────────────────────────────

    [Fact]
    public async Task Lookup_GoBangEncodedName_UnderDecodedReservation_MakesNoRequest()
    {
        // github.com/!burnt!sushi/toml is the proxy spelling of github.com/BurntSushi/toml, and the
        // @latest URL built from it names that module upstream. The reservation is matched on the
        // decoded path, so the encoded spelling cannot slip past it.
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("golang");
        await _reserved.AddAsync(orgId, "golang", "github.com/BurntSushi", createdBy: null);
        var lookup = BuildLookup(handler);

        var noVersion = await lookup.LookupAsync(
            new PackageLookupRequest(orgId, "golang", "github.com/!burnt!sushi/toml", null));
        var mixed = await lookup.LookupAsync(
            new PackageLookupRequest(orgId, "golang", "github.com/!burnt!sushi/Toml", "v1.0.0"));

        Assert.Equal(PackageLookupStatus.Reserved, noVersion.Status);
        Assert.Equal(PackageLookupStatus.Ok, mixed.Status);
        Assert.Empty(handler.Urls);
    }

    [Fact]
    public async Task Lookup_GoBangEncodedTwin_ReachesUpstreamOnce()
    {
        // Adversarial twin: !burnt!sushicorp decodes to BurntSushicorp, past the slash boundary of
        // the reservation, so it still goes upstream, under its encoded spelling.
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("golang");
        await _reserved.AddAsync(orgId, "golang", "github.com/BurntSushi", createdBy: null);

        var outcome = await BuildLookup(handler).LookupAsync(
            new PackageLookupRequest(orgId, "golang", "github.com/!burnt!sushicorp/toml", null));

        Assert.Equal(PackageLookupStatus.UpstreamNotFound, outcome.Status);
        Assert.Equal($"{UpstreamUrl}/github.com/!burnt!sushicorp/toml/@latest", Assert.Single(handler.Urls));
    }

    [Fact]
    public async Task Resolver_GoBangEncodedName_UnderDecodedReservation_ReturnsReserved()
    {
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("golang");
        await _reserved.AddAsync(orgId, "golang", "github.com/BurntSushi", createdBy: null);
        var resolver = BuildResolver(handler);

        var encoded = await resolver.ResolveAsync("golang", orgId, "github.com/!burnt!sushi/toml");
        var decoded = await resolver.ResolveAsync("golang", orgId, "github.com/BurntSushi/toml");

        Assert.True(encoded.IsReserved);
        Assert.True(decoded.IsReserved);
        Assert.Empty(handler.Urls);
    }

    [Theory]
    [InlineData("github.com/acme/x!!y")]
    [InlineData("github.com/acme/!1x")]
    [InlineData("github.com/!Acme/x")]
    [InlineData("github.com/acme/x!")]
    public async Task GoNameWithInvalidBangSequence_FailsClosed_WithoutAnyRequest(string name)
    {
        // A '!' that is not a valid bang escape names no module the reservation check can match,
        // so it is treated as reserved rather than passed upstream unchecked, even in an org with
        // no Go reservation at all.
        var handler = new RecordingHandler();
        string orgId = await SeedOrgAsync("golang");

        var latest = await BuildResolver(handler).ResolveAsync("golang", orgId, name);
        var outcome = await BuildLookup(handler).LookupAsync(new PackageLookupRequest(orgId, "golang", name, null));

        Assert.True(latest.IsReserved);
        Assert.NotEqual(PackageLookupStatus.UpstreamNotFound, outcome.Status);
        Assert.NotEqual(PackageLookupStatus.Ok, outcome.Status);
        Assert.Empty(handler.Urls);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private async Task<string> SeedOrgAsync(string ecosystem, string url = UpstreamUrl)
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"org-{Guid.NewGuid():N}");
        var registries = new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured());
        // A Hex upstream with no public key is never consulted at all, so it carries one here:
        // otherwise a Hex case would read as "no request" whether or not the name is reserved.
        await registries.AddAsync(orgId, ecosystem == "hex"
            ? new NewUpstreamRegistry("hex", url, PublicKeyPem: HexRegistrySigner.ExportPublicKeyPem(_hexKey))
            : new NewUpstreamRegistry(ecosystem, url));
        return orgId;
    }

    private UpstreamClient BuildUpstreamClient(HttpMessageHandler handler)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dep-reserved-eco-{Guid.NewGuid():N}"),
            })
            .Build();
        var urlValidator = Substitute.For<IUpstreamUrlValidator>();
        urlValidator.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(UpstreamUrlBlock.None));
        return new UpstreamClient(
            new StaticHttpClientFactory(new HttpClient(handler)),
            new TieredBlobStorage(_blobs, _blobs),
            new AuditRepository(_db),
            urlValidator,
            Substitute.For<IAirGapMode>(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
    }

    private UpstreamRegistryResolver BuildRegistries() =>
        new(new UpstreamRegistryRepository(_db, TimeProvider.System, TestEnvelope.Unconfigured()));

    private UpstreamLatestVersionResolver BuildResolver(HttpMessageHandler handler) =>
        new(BuildUpstreamClient(handler), BuildRegistries(), _reserved);

    private ProxyVersionRecorder BuildRecorder(HttpMessageHandler handler) =>
        new(new PackageRepository(_db), new AuditRepository(_db),
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)), new CacheArtifactRepository(_db),
            BuildResolver(handler), NullLogger<ProxyVersionRecorder>.Instance);

    private PackageLookupService BuildLookup(HttpMessageHandler handler)
    {
        var upstream = BuildUpstreamClient(handler);
        var registries = BuildRegistries();
        var osv = Substitute.For<IOsvSource>();
        osv.TryQueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new OsvQueryResult(new List<OsvAdvisory>(), true)));
        return new PackageLookupService(
            new OrgRepository(_db), registries, upstream,
            new UpstreamLatestVersionResolver(upstream, registries, _reserved),
            osv, new VulnerabilityRepository(_db, TimeProvider.System),
            new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db)),
            Substitute.For<IAirGapMode>(), TimeProvider.System, new PackageLookupCache(TimeProvider.System), _reserved);
    }

    private async Task<string> SeedNpmCacheArtifactAsync(string orgId, string name, string version, int? versionsBehind)
    {
        await using var conn = await _db.OpenAsync();
        string caId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl, versions_behind)
            VALUES (@id, 'npm', @name, @version, @filename, @blobKey, 'h', @purl, @versionsBehind)
            """,
            new
            {
                id = caId,
                name,
                version,
                filename = $"pkg-{version}.tgz",
                blobKey = $"proxy/{caId}/pkg-{version}.tgz",
                purl = PurlNormalizer.Npm(name, version),
                versionsBehind,
            });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
            new { orgId, caId });
        return caId;
    }

    private async Task<ProxyVersionRequest> BuildNpmRequestAsync(string orgId, string name, string version)
    {
        byte[] bytes = Encoding.UTF8.GetBytes($"tarball-{name}-{version}");
        string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string key = BlobKeys.Proxy(sha);
        await _blobs.PutAsync(key, new MemoryStream(bytes));
        var blob = new BlobHandle(key, sha, bytes.LongLength,
            async ct => await _blobs.GetAsync(key, ct) ?? throw new InvalidOperationException("blob vanished"));
        return new ProxyVersionRequest(
            OrgId: orgId, Ecosystem: "npm", PackageName: name, PurlName: name,
            Version: version, Purl: PurlNormalizer.Npm(name, version),
            Sha256: sha, File: $"pkg-{version}.tgz", Blob: blob, AuditActorId: null);
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    /// <summary>
    /// Records every outbound request URL in order. Answers 404 by default, so an unreserved name
    /// costs exactly one request per ecosystem; a responder can be supplied for the secondary-fetch
    /// cases.
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<string, HttpResponseMessage> _respond;

        public RecordingHandler(Func<string, HttpResponseMessage>? respond = null)
            => _respond = respond ?? (_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        public List<string> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string url = request.RequestUri!.ToString();
            lock (Urls)
            {
                Urls.Add(url);
            }

            return Task.FromResult(_respond(url));
        }
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }
}
