using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Amazon.S3;
using Amazon.S3.Model;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Integration;

/// <summary>
/// The object-store round-trips a redirected cache hit costs, counted at the S3 API boundary.
/// The Go, apk, Terraform, Hex, and Cargo serve paths decide hit-or-miss by asking whether the
/// blob is there, then gate, then redirect; the redirect's signer must not ask the same question
/// again. The npm, PyPI, and NuGet GET paths gate first and let the redirect's check be the only
/// one, and are pinned here alongside them, hosted artefacts included.
/// The store under test is the real <see cref="S3BlobStore"/> over a substituted
/// <see cref="IAmazonS3"/> that answers from an in-memory store and counts each call, so a second
/// HEAD from anywhere on the path — call site, seam, or store signer — shows up as a count of two.
///
/// <para>
/// The twins pin what the single check must not give up: a blob that is gone behind its row is
/// never redirected (the one HEAD finds it missing and the request falls through to the miss
/// path), and a blocked hit has no URL minted for it.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class PresignedRedirectExistenceCheckTests : IAsyncLifetime
{
    private const string Bucket = "presign-test";
    private const string UrlBase = "https://presign-test.s3.test/";

    private readonly DependablyFactory _factory;
    private readonly InMemoryBlobStore _objects;
    private readonly IAmazonS3 _s3 = Substitute.For<IAmazonS3>();
    private readonly ConcurrentQueue<string> _heads = new();
    private readonly ConcurrentQueue<string> _gets = new();
    private readonly ConcurrentQueue<string> _presigned = new();
    private string _orgId = "";
    private string _pullToken = "";

    public PresignedRedirectExistenceCheckTests()
    {
        var store = new S3BlobStore(_s3, Bucket);
        var options = new PresignedReadOptions
        {
            Enabled = true,
            Ttl = TimeSpan.FromSeconds(60),
            Ecosystems = PresignedReadOptions.RedirectableEcosystems,
        };
        _factory = new DependablyFactory
        {
            ServiceOverrides = services =>
            {
                services.RemoveAll<IBlobStore>();
                services.AddSingleton<IBlobStore>(store);
                services.RemoveAll<TieredBlobStorage>();
                services.AddSingleton(new TieredBlobStorage(store, store));
                services.RemoveAll<BlobPresignService>();
                services.AddScoped(sp => new BlobPresignService(
                    options, sp.GetRequiredService<TimeProvider>(), NullLogger<BlobPresignService>.Instance));
            },
        };
        _objects = _factory.BlobStore;
        WireS3();
    }

    public async Task InitializeAsync()
    {
        await _factory.InitializeAsync();
        var org = await _factory.Services.GetRequiredService<OrgRepository>().GetBySlugAsync("default");
        _orgId = org!.Id;
        _pullToken = await _factory.CreateToken("pull");
    }

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    public static TheoryData<string> ProbingEcosystems => new("apk", "cargo", "go", "hex", "npm", "nuget", "pypi", "terraform");

    [Theory]
    [MemberData(nameof(ProbingEcosystems))]
    public async Task RedirectedHit_AsksTheStoreWhetherTheBlobExistsExactlyOnce(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        using var client = Client();
        ClearCounts();

        using var response = await client.GetAsync(seeded.Url);

        Assert.Equal(ecosystem == "apk" ? HttpStatusCode.Found : HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.StartsWith(UrlBase, response.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.Equal([seeded.Key], _heads.ToArray());
        Assert.Equal([seeded.Key], _presigned.ToArray());
        Assert.Empty(_gets);
    }

    [Theory]
    [MemberData(nameof(ProbingEcosystems))]
    public async Task MissingBlob_IsNeverRedirected_AndFallsThroughToTheMissPath(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        await _objects.DeleteAsync(seeded.Key);
        using var client = Client();
        ClearCounts();

        using var response = await client.GetAsync(seeded.Url);

        Assert.False(response.StatusCode is HttpStatusCode.TemporaryRedirect or HttpStatusCode.Found,
            $"{ecosystem}: expected no redirect, was {(int)response.StatusCode}");
        Assert.False(response.Headers.TryGetValues("X-Cache", out var cache) && cache.Contains("HIT"),
            $"{ecosystem}: a blob gone behind its row is a miss, not a hit");
        Assert.Empty(_presigned);
        Assert.Contains(seeded.Key, _heads);
    }

    [Theory]
    [MemberData(nameof(ProbingEcosystems))]
    public async Task BlockedHit_IsRefusedWithoutMintingAUrl(string ecosystem)
    {
        var seeded = await SeedAsync(ecosystem);
        await BlockAsync(seeded);
        using var client = Client();
        ClearCounts();

        using var response = await client.GetAsync(seeded.Url);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_presigned);
        // A path that probes before gating asks once; one that gates first never asks.
        Assert.True(_heads.Count <= 1 && _heads.All(k => k == seeded.Key),
            $"{ecosystem}: expected at most one existence check, saw {_heads.Count}");
    }

    // ── The substituted S3 API ─────────────────────────────────────────────────

    private void WireS3()
    {
        _s3.GetObjectMetadataAsync(Bucket, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(async ci =>
            {
                string key = ci.ArgAt<string>(1);
                _heads.Enqueue(key);
                return await _objects.ExistsAsync(key)
                    ? new GetObjectMetadataResponse()
                    : throw new AmazonS3Exception("Not Found") { StatusCode = HttpStatusCode.NotFound };
            });

        _s3.GetObjectAsync(Bucket, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(async ci =>
            {
                string key = ci.ArgAt<string>(1);
                _gets.Enqueue(key);
                return await _objects.GetAsync(key) is { } body
                    ? new GetObjectResponse { ResponseStream = body }
                    : throw new AmazonS3Exception("Not Found") { StatusCode = HttpStatusCode.NotFound };
            });

        _s3.PutObjectAsync(Arg.Any<PutObjectRequest>(), Arg.Any<CancellationToken>())
            .Returns(async ci =>
            {
                var request = ci.ArgAt<PutObjectRequest>(0);
                await _objects.PutAsync(request.Key, request.InputStream);
                return new PutObjectResponse();
            });

        _s3.GetPreSignedURLAsync(Arg.Any<GetPreSignedUrlRequest>())
            .Returns(ci =>
            {
                string key = ci.ArgAt<GetPreSignedUrlRequest>(0).Key;
                _presigned.Enqueue(key);
                return Task.FromResult($"{UrlBase}{key}?X-Amz-Signature=test");
            });
    }

    private void ClearCounts()
    {
        _heads.Clear();
        _gets.Clear();
        _presigned.Clear();
    }

    // ── Seeding ────────────────────────────────────────────────────────────────

    /// <summary>
    /// A seeded artefact: its download URL, the store key behind it, the name its rows carry, and
    /// whether it is a hosted (published) version rather than a cache hit.
    /// </summary>
    private sealed record Seeded(string Url, string Key, string Marker, bool Hosted = false);

    private async Task<Seeded> SeedAsync(string ecosystem)
    {
        string u = "px" + Guid.NewGuid().ToString("N")[..10];
        switch (ecosystem)
        {
            case "go":
                {
                    string module = $"example.com/{u}";
                    string key = BlobKeys.Go(_orgId, module, "v1.0.0", "zip");
                    await SeedCacheHitAsync("golang", module, "v1.0.0", "v1.0.0.zip", key);
                    return new Seeded($"/go/{module}/@v/v1.0.0.zip", key, module);
                }

            case "apk":
                {
                    string file = $"{u}-1.0.0-r0.apk";
                    string key = BlobKeys.Apk(_orgId, "v3.19", "main", "x86_64", file);
                    await SeedCacheHitAsync("apk", u, "1.0.0-r0", $"main/x86_64/{file}", key);
                    return new Seeded($"/apk/v3.19/main/x86_64/{file}", key, u);
                }

            case "terraform":
                {
                    string provider = $"registry.terraform.io/{u}/null";
                    string key = BlobKeys.Terraform(_orgId, "registry.terraform.io", u, "null", "1.0.0", "linux_amd64");
                    await SeedCacheHitAsync("terraform", provider, "1.0.0", "linux_amd64.zip", key);
                    return new Seeded($"/terraform/{provider}/1.0.0/linux_amd64.zip", key, u);
                }

            case "cargo":
                {
                    string key = BlobKeys.Cargo(_orgId, u, "1.0.0");
                    await SeedCacheHitAsync("cargo", u, "1.0.0", $"{u}-1.0.0.crate", key);
                    return new Seeded($"/cargo/api/v1/crates/{u}/1.0.0/download", key, u);
                }

            case "npm":
                await _factory.PushNpmPackage(u, "1.0.0");
                return await HostedAsync($"/npm/tarballs/{u}/{u}-1.0.0.tgz", u);

            case "nuget":
                await _factory.PushNuGetPackage(u, "1.0.0");
                return await HostedAsync($"/nuget/flatcontainer/{u}/1.0.0/{u}.1.0.0.nupkg", u);

            case "pypi":
                {
                    await _factory.PushPyPiPackage(u, "1.0.0");
                    using var client = Client();
                    string index = await client.GetStringAsync($"/simple/{u}/");
                    string href = index.Split("href=\"")[1].Split('"')[0].Split('#')[0];
                    return await HostedAsync(href, u);
                }

            case "hex":
                {
                    string key = BlobKeys.Hex(_orgId, u, "1.0.0");
                    await SeedCacheHitAsync("hex", u, "1.0.0", $"{u}-1.0.0.tar", key);
                    return new Seeded($"/hex/tarballs/{u}-1.0.0.tar", key, u);
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(ecosystem), ecosystem, "No seed for this ecosystem.");
        }
    }

    /// <summary>
    /// A published version's store key is chosen by the publish pipeline, so it is read off the
    /// URL the first redirect signs rather than reconstructed here.
    /// </summary>
    private async Task<Seeded> HostedAsync(string url, string marker)
    {
        ClearCounts();
        using var client = Client();
        using var first = await client.GetAsync(url);
        Assert.Equal(HttpStatusCode.TemporaryRedirect, first.StatusCode);
        return new Seeded(url, Assert.Single(_presigned), marker, Hosted: true);
    }

    private async Task SeedCacheHitAsync(string ecosystem, string name, string version, string filename, string blobKey)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(64);
        await _objects.PutAsync(blobKey, new MemoryStream(bytes));

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            _orgId, ecosystem, name, version, filename,
            Sha256: Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            SizeBytes: bytes.Length, BlobKey: blobKey,
            UpstreamUrl: $"https://upstream.example/{filename}", Origin: CacheAccessOrigin.FirstFetch));
        Assert.NotNull(id);
    }

    private async Task BlockAsync(Seeded seeded)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync(
            seeded.Hosted
                ? """
                  UPDATE package_versions SET manual_block_state = 'blocked'
                  WHERE package_id IN (SELECT id FROM packages WHERE org_id = @orgId AND (name LIKE @like OR purl_name LIKE @like))
                  """
                : """
                  UPDATE tenant_artifact_access SET manual_block_state = 'blocked'
                  WHERE org_id = @orgId AND cache_artifact_id IN (SELECT id FROM cache_artifact WHERE name LIKE @like)
                  """,
            new { orgId = _orgId, like = $"%{seeded.Marker}%" });
    }

    private HttpClient Client()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _pullToken);
        return client;
    }
}
