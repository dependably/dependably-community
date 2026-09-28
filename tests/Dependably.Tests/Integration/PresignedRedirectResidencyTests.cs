using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins, per ecosystem and per plane, the origin each serve site hands the redirect seam.
///
/// <para>
/// The store signer ignores origin, so a suite that only runs it cannot tell a serve site that
/// passes <see cref="BlobOrigin.Uploaded"/> from one that passes <see cref="BlobOrigin.Proxied"/>.
/// This class runs the CloudFront signer with no uncached path prefix — the residency-safe
/// default — where the two are visibly different: an uploaded artefact's redirect must be signed
/// by the object store (never CloudFront), and a proxied artefact's must be signed under the
/// CloudFront cached prefix. A hosted serve site that mislabels its row as proxied sends the
/// customer's own bytes to the CDN, and fails here.
/// </para>
///
/// <para>
/// Both planes are seeded for every ecosystem that has both: hosted artefacts through the publish
/// routes (or, for Cargo and Hex, a hosted <c>package_versions</c> row and its blob), proxied ones
/// as the cache hit a first fetch leaves behind.
/// </para>
///
/// <para>
/// A proxied artefact is edge-cacheable only while every upstream the org has configured for its
/// ecosystem is credential-free. Each proxied ecosystem is also run with one credentialed upstream
/// added — OCI Basic, a bearer token elsewhere — where the same cache hit must be signed by the
/// object store, and with the visibility lookup failing, where it must too.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PresignedRedirectResidencyTests : IAsyncLifetime
{
    private const string CloudFrontBase = "https://d111111abcdef8.cloudfront.net";

    private readonly DependablyFactory _factory;
    private readonly PresigningBlobStore _store;
    private readonly RSA _key = RSA.Create(2048);
    private readonly FailableVisibility _visibility = new();
    private string _orgId = "";
    private string _pullToken = "";
    private bool _rpmPushed;

    public PresignedRedirectResidencyTests()
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
                services.RemoveAll<PresignedReadOptions>();
                services.AddSingleton(new PresignedReadOptions
                {
                    Enabled = true,
                    Ttl = TimeSpan.FromSeconds(60),
                    Ecosystems = PresignedReadOptions.RedirectableEcosystems,
                    Signer = PresignedReadSigner.CloudFront,
                    CloudFront = new CloudFrontSignerOptions
                    {
                        UrlBase = new Uri(CloudFrontBase),
                        KeyPairId = "K2JCJMDEHXQW5F",
                        PrivateKey = _key,
                        CachedPathPrefix = "cached",
                        UncachedPathPrefix = null,
                    },
                });
                services.RemoveAll<BlobPresignService>();
                services.AddSingleton(sp =>
                {
                    _visibility.Inner = new UpstreamProxiedContentVisibility(
                        sp.GetRequiredService<UpstreamRegistryRepository>(), sp.GetRequiredService<IEdgeMode>());
                    return new BlobPresignService(
                        sp.GetRequiredService<PresignedReadOptions>(), sp.GetRequiredService<TimeProvider>(),
                        NullLogger<BlobPresignService>.Instance, _visibility);
                });
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

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        _key.Dispose();
    }

    public static TheoryData<string> HostedEcosystems => new(["cargo", "hex", "maven", "npm", "nuget", "oci", "pypi", "rpm"]);

    public static TheoryData<string> ProxiedEcosystems => new(PresignedReadOptions.RedirectableEcosystems.Order(StringComparer.Ordinal));

    [Theory]
    [MemberData(nameof(HostedEcosystems))]
    public async Task UploadedArtefact_IsSignedByTheStore_NeverThroughCloudFront(string ecosystem)
    {
        string url = await SeedHostedAsync(ecosystem);

        string location = await RedirectLocationAsync(url);

        Assert.StartsWith(PresigningBlobStore.UrlBase, location, StringComparison.Ordinal);
        Assert.Single(_store.Signed);
    }

    [Theory]
    [MemberData(nameof(ProxiedEcosystems))]
    public async Task ProxiedArtefact_FromAnOrgWithOnlyAnonymousUpstreams_IsSignedUnderTheCloudFrontCachedPrefix(string ecosystem)
    {
        await EnsureOnlyAnonymousUpstreamsAsync(ecosystem);
        string url = await SeedProxiedAsync(ecosystem);

        string location = await RedirectLocationAsync(url);

        Assert.StartsWith($"{CloudFrontBase}/cached/", location, StringComparison.Ordinal);
        Assert.Empty(_store.Signed);
    }

    [Theory]
    [MemberData(nameof(ProxiedEcosystems))]
    public async Task ProxiedArtefact_FromAnOrgWithACredentialedUpstream_IsSignedByTheStore_NeverUnderTheCachedPrefix(string ecosystem)
    {
        await EnsureOnlyAnonymousUpstreamsAsync(ecosystem);
        await AddCredentialedUpstreamAsync(ecosystem);
        string url = await SeedProxiedAsync(ecosystem);

        string location = await RedirectLocationAsync(url);

        Assert.StartsWith(PresigningBlobStore.UrlBase, location, StringComparison.Ordinal);
        Assert.DoesNotContain("/cached/", location, StringComparison.Ordinal);
        Assert.Single(_store.Signed);
    }

    [Theory]
    [MemberData(nameof(ProxiedEcosystems))]
    public async Task ProxiedArtefact_WhenTheVisibilityLookupFails_IsSignedByTheStore(string ecosystem)
    {
        await EnsureOnlyAnonymousUpstreamsAsync(ecosystem);
        string url = await SeedProxiedAsync(ecosystem);
        _visibility.Fail = true;

        string location = await RedirectLocationAsync(url);

        Assert.StartsWith(PresigningBlobStore.UrlBase, location, StringComparison.Ordinal);
        Assert.Single(_store.Signed);
    }

    [Fact]
    public async Task OneOrg_CredentialedOciUpstreamAndAnonymousNpmUpstream_OnlyTheNpmArtefactIsEdgeCacheable()
    {
        // The rule is per (org, ecosystem): a Basic-auth OCI upstream makes every proxied OCI
        // layer private — the Docker Hub one included, since nothing records which upstream
        // supplied it — and leaves the same org's anonymous npm upstream's tarballs cacheable.
        await EnsureOnlyAnonymousUpstreamsAsync("oci");
        await EnsureOnlyAnonymousUpstreamsAsync("npm");
        await AddCredentialedUpstreamAsync("oci");

        string layer = await RedirectLocationAsync(await SeedProxiedAsync("oci"));
        string tarball = await RedirectLocationAsync(await SeedProxiedAsync("npm"));

        Assert.StartsWith(PresigningBlobStore.UrlBase, layer, StringComparison.Ordinal);
        Assert.StartsWith($"{CloudFrontBase}/cached/", tarball, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("oci")]
    [InlineData("npm")]
    public async Task ProxiedArtefact_AfterItsCredentialedUpstreamIsDeleted_IsStillSignedByTheStore(string ecosystem)
    {
        // Only anonymous upstreams remain, but objects the deleted one fetched are still cached and
        // nothing records which upstream fetched them: the org stays private for the ecosystem.
        await EnsureOnlyAnonymousUpstreamsAsync(ecosystem);
        var repo = _factory.Services.GetRequiredService<UpstreamRegistryRepository>();
        var added = ecosystem == "oci"
            ? await repo.AddOciAsync(_orgId, new NewOciUpstreamRegistry(
                Host: "registry.private.example", AuthType: OciAuthType.Basic, Prefixes: ["residency/"], Username: "robot"))
            : await repo.AddAsync(_orgId, new NewUpstreamRegistry(
                ecosystem, "https://npm.private.example", AuthType: "basic", Username: "robot"));
        string url = await SeedProxiedAsync(ecosystem);

        await repo.DeleteAsync(_orgId, added.Id);

        Assert.All(await repo.ListAsync(_orgId), r =>
            Assert.True(r.Ecosystem != ecosystem || UpstreamRegistryRepository.IsCredentialFree(r.AuthType, r.Username, r.HasSecret, r.Url)));
        string location = await RedirectLocationAsync(url);
        Assert.StartsWith(PresigningBlobStore.UrlBase, location, StringComparison.Ordinal);
        Assert.DoesNotContain("/cached/", location, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxiedArtefact_WhoseCredentialedUpstreamOnlyTheAuditLogRemembers_IsSignedByTheStore()
    {
        // A credentialed upstream added and deleted before the history table existed leaves only
        // its audit event. The startup convergence reads it, and the org stays private.
        await EnsureOnlyAnonymousUpstreamsAsync("npm");
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO audit_log (id, scope, org_id, action, detail, created_at)
                VALUES (@id, 'tenant', @orgId, 'upstream_registry_added', @detail, @createdAt)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = _orgId,
                    detail = """{"id":"gone","ecosystem":"npm","url":"https://npm.private.example","name":null,"authType":"bearer","hasSecret":true,"protocol":null,"hasPublicKey":false}""",
                    createdAt = _factory.Services.GetRequiredService<TimeProvider>().GetUtcNow().AddDays(-1).ToUtcIso(),
                });
        }

        string before = await RedirectLocationAsync(await SeedProxiedAsync("npm"));
        await _factory.Services.GetRequiredService<SchemaInitializer>().InitializeAsync();
        string after = await RedirectLocationAsync(await SeedProxiedAsync("npm"));

        Assert.StartsWith($"{CloudFrontBase}/cached/", before, StringComparison.Ordinal);
        Assert.StartsWith(PresigningBlobStore.UrlBase, after, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProxiedArtefact_ForAnEcosystemWithNoUpstreamLeft_IsSignedByTheStore()
    {
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM upstream_registry WHERE org_id = @orgId AND ecosystem = 'npm'", new { orgId = _orgId });
        }

        string location = await RedirectLocationAsync(await SeedProxiedAsync("npm"));

        Assert.StartsWith(PresigningBlobStore.UrlBase, location, StringComparison.Ordinal);
    }

    // ── Upstream configuration ────────────────────────────────────────────────

    private static string UpstreamEcosystem(string ecosystem) => ecosystem == "go" ? "golang" : ecosystem;

    /// <summary>
    /// Leaves the org with credential-free upstreams only for <paramref name="ecosystem"/>: the
    /// seeded defaults where they are anonymous, plus one anonymous row where none is seeded.
    /// </summary>
    private async Task EnsureOnlyAnonymousUpstreamsAsync(string ecosystem)
    {
        string eco = UpstreamEcosystem(ecosystem);
        var repo = _factory.Services.GetRequiredService<UpstreamRegistryRepository>();
        if (ecosystem == "oci")
        {
            await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
            await UpstreamRegistrySeeder.SeedOciDefaultsForOrgAsync(conn, _orgId);
        }
        else if ((await repo.ListSourcesForEcosystemAsync(_orgId, eco)).Count == 0)
        {
            await repo.AddAsync(_orgId, new NewUpstreamRegistry(eco, $"https://public-{eco}.example"));
        }

        Assert.True(await repo.AllUpstreamsCredentialFreeAsync(_orgId, eco));
    }

    /// <summary>
    /// A private upstream for <paramref name="ecosystem"/>: OCI Basic auth, a bearer token everywhere
    /// else. Written as a row, as the management API leaves it; the secret is stored as legacy
    /// plaintext because this factory runs without a master key.
    /// </summary>
    private async Task AddCredentialedUpstreamAsync(string ecosystem)
    {
        string eco = UpstreamEcosystem(ecosystem);
        bool oci = ecosystem == "oci";
        await using (var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, username, secret, prefixes)
                VALUES (@id, @orgId, @eco, @url, 99, @authType, @username, 'n0t-a-real-secret', @prefixes)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId = _orgId,
                    eco,
                    url = oci ? "registry.private.example" : $"https://private-{eco}.example",
                    authType = oci ? "basic" : "bearer",
                    username = oci ? "robot" : null,
                    prefixes = oci ? "[\"residency/\"]" : null,
                });
        }

        Assert.False(await _factory.Services.GetRequiredService<UpstreamRegistryRepository>()
            .AllUpstreamsCredentialFreeAsync(_orgId, eco));
    }

    /// <summary>The production visibility rule, with a switch that makes its lookup throw.</summary>
    private sealed class FailableVisibility : IProxiedContentVisibility
    {
        public IProxiedContentVisibility? Inner { get; set; }

        public bool Fail { get; set; }

        public Task<bool> IsPublicAsync(string orgId, string ecosystem, CancellationToken ct = default)
            => Fail ? throw new InvalidOperationException("upstream lookup failed") : Inner!.IsPublicAsync(orgId, ecosystem, ct);
    }

    private async Task<string> RedirectLocationAsync(string url)
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _pullToken);
        using var response = await client.GetAsync(url);
        // apk redirects with 302, every other ecosystem with 307.
        Assert.True(response.StatusCode is HttpStatusCode.TemporaryRedirect or HttpStatusCode.Found,
            $"expected a presigned redirect, was {(int)response.StatusCode}");
        return response.Headers.Location!.AbsoluteUri;
    }

    // ── Hosted plane ───────────────────────────────────────────────────────────

    private async Task<string> SeedHostedAsync(string ecosystem)
    {
        _store.ClearSigned();
        string u = "rs" + Guid.NewGuid().ToString("N")[..10];
        switch (ecosystem)
        {
            case "npm":
                await _factory.PushNpmPackage(u, "1.0.0");
                return $"/npm/tarballs/{u}/{u}-1.0.0.tgz";

            case "pypi":
                {
                    await _factory.PushPyPiPackage(u, "1.0.0");
                    using var client = _factory.CreateClientWithBearer(_pullToken);
                    string index = await client.GetStringAsync($"/simple/{u}/");
                    return index.Split("href=\"")[1].Split('"')[0].Split('#')[0];
                }

            case "nuget":
                await _factory.PushNuGetPackage(u, "1.0.0");
                return $"/nuget/flatcontainer/{u}/1.0.0/{u}.1.0.0.nupkg";

            case "maven":
                return $"/maven/com/{u}/lib/1.0.0/{await _factory.PushMavenArtifact($"com.{u}", "lib", "1.0.0")}";

            case "rpm":
                if (!_rpmPushed)
                {
                    await _factory.PushRpmPackage();
                    _rpmPushed = true;
                }

                return "/rpm/packages/testpkg-1.0-1.x86_64.rpm";

            case "oci":
                {
                    string repo = $"residency/{u}";
                    byte[] layer = RandomNumberGenerator.GetBytes(128);
                    string digest = "sha256:" + Convert.ToHexString(SHA256.HashData(layer)).ToLowerInvariant();
                    using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
                    using var created = await push.PostAsync($"/v2/{repo}/blobs/uploads/?digest={digest}", new ByteArrayContent(layer));
                    Assert.Equal(HttpStatusCode.Created, created.StatusCode);
                    return $"/v2/{repo}/blobs/{digest}";
                }

            case "cargo":
                await SeedHostedRowAsync("cargo", u, $"pkg:cargo/{u}@1.0.0", $"{u}-1.0.0.crate");
                return $"/cargo/api/v1/crates/{u}/1.0.0/download";

            case "hex":
                await SeedHostedRowAsync("hex", u, $"pkg:hex/{u}@1.0.0", $"{u}-1.0.0.tar");
                return $"/hex/tarballs/{u}-1.0.0.tar";

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No hosted seed for this ecosystem.");
        }
    }

    /// <summary>A hosted version row and its blob, as the ecosystem's publish path leaves them.</summary>
    private async Task SeedHostedRowAsync(string ecosystem, string name, string purl, string filename)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        byte[] bytes = RandomNumberGenerator.GetBytes(64);
        string blobKey = BlobKeys.Hosted(_orgId, ecosystem, name, "1.0.0", filename);
        await _store.Inner.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes));

        string packageId = await PackageSeeder.InsertAsync(db, _orgId, ecosystem, name);
        await PackageSeeder.InsertVersionAsync(db, packageId, "1.0.0", purl, origin: "uploaded",
            blobKey: blobKey, sizeBytes: bytes.Length,
            checksumSha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
    }

    // ── Proxied plane ──────────────────────────────────────────────────────────

    private async Task<string> SeedProxiedAsync(string ecosystem)
    {
        _store.ClearSigned();
        string u = "rs" + Guid.NewGuid().ToString("N")[..10];
        switch (ecosystem)
        {
            case "npm":
                await SeedContentAddressedAsync("npm", u, "1.0.0", $"{u}-1.0.0.tgz");
                return $"/npm/tarballs/{u}/{u}-1.0.0.tgz";

            case "pypi":
                {
                    string file = $"{u}-1.0.0-py3-none-any.whl";
                    await SeedContentAddressedAsync("pypi", u, "1.0.0", file);
                    return $"/packages/{file}";
                }

            case "nuget":
                await SeedContentAddressedAsync("nuget", u, "1.0.0", $"{u}.1.0.0.nupkg");
                return $"/nuget/flatcontainer/{u}/1.0.0/{u}.1.0.0.nupkg";

            case "maven":
                await SeedContentAddressedAsync("maven", $"com.{u}:lib", "1.0.0", "lib-1.0.0.jar");
                return $"/maven/com/{u}/lib/1.0.0/lib-1.0.0.jar";

            case "rpm":
                {
                    string file = $"{u}-1.0-1.x86_64.rpm";
                    await SeedContentAddressedAsync("rpm", u, "1.0-1", file);
                    return $"/rpm/packages/{file}";
                }

            case "oci":
                return await SeedProxiedOciAsync(u);

            case "go":
                {
                    string module = $"example.com/{u}";
                    await SeedCacheHitAsync("golang", module, "v1.0.0", "v1.0.0.zip", BlobKeys.Go(_orgId, module, "v1.0.0", "zip"));
                    return $"/go/{module}/@v/v1.0.0.zip";
                }

            case "cargo":
                await SeedCacheHitAsync("cargo", u, "1.0.0", $"{u}-1.0.0.crate", BlobKeys.Cargo(_orgId, u, "1.0.0"));
                return $"/cargo/api/v1/crates/{u}/1.0.0/download";

            case "apk":
                {
                    string file = $"{u}-1.0.0-r0.apk";
                    await SeedCacheHitAsync("apk", u, "1.0.0-r0", $"main/x86_64/{file}", BlobKeys.Apk(_orgId, "v3.19", "main", "x86_64", file));
                    return $"/apk/v3.19/main/x86_64/{file}";
                }

            case "terraform":
                {
                    string provider = $"registry.terraform.io/{u}/null";
                    await SeedCacheHitAsync("terraform", provider, "1.0.0", "linux_amd64.zip",
                        BlobKeys.Terraform(_orgId, "registry.terraform.io", u, "null", "1.0.0", "linux_amd64"));
                    return $"/terraform/{provider}/1.0.0/linux_amd64.zip";
                }

            case "hex":
                await SeedCacheHitAsync("hex", u, "1.0.0", $"{u}-1.0.0.tar", BlobKeys.Hex(_orgId, u, "1.0.0"));
                return $"/hex/tarballs/{u}-1.0.0.tar";

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No proxied seed for this ecosystem.");
        }
    }

    /// <summary>A proxied artefact under the shared content-addressed proxy key, as npm/PyPI/NuGet/Maven/RPM store it.</summary>
    private async Task SeedContentAddressedAsync(string ecosystem, string name, string version, string filename)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(64);
        string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        await SeedCacheHitAsync(ecosystem, name, version, filename, $"{BlobKeys.Proxy(sha)}/{filename}", bytes);
    }

    private async Task SeedCacheHitAsync(
        string ecosystem, string name, string version, string filename, string blobKey, byte[]? bytes = null)
    {
        bytes ??= RandomNumberGenerator.GetBytes(64);
        await _store.Inner.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes));

        string? id = await _factory.Services.GetRequiredService<CacheAccessRecorder>().RecordAccessAsync(new CacheAccess(
            _orgId, ecosystem, name, version, filename,
            Sha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            SizeBytes: bytes.Length, BlobKey: blobKey,
            UpstreamUrl: $"https://upstream.example/{filename}", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(id);
    }

    private async Task<string> SeedProxiedOciAsync(string u)
    {
        string repo = $"residency/{u}";
        byte[] layer = RandomNumberGenerator.GetBytes(128);
        string hex = Convert.ToHexString(SHA256.HashData(layer)).ToLowerInvariant();
        string digest = "sha256:" + hex;
        string blobKey = BlobKeys.OciBlob("sha256", hex);
        await _store.Inner.PutAsync(blobKey, new MemoryStream(layer));

        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/octet-stream', @size, @blobKey, 'proxy')
            """,
            new { digest, orgId = _orgId, size = (long)layer.Length, blobKey });
        return $"/v2/{repo}/blobs/{digest}";
    }
}
