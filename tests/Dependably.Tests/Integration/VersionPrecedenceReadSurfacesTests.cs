using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Regression tests for Cargo's <c>max_version</c> and NuGet's Search Query Service resolving
/// "latest version" by SemVer precedence (<see cref="Dependably.Infrastructure.VersionPrecedenceResolver"/>)
/// rather than by <c>CreatedAt</c>/<c>first_cached_at</c> recency.
///
/// Every test explicitly stamps each version's <c>created_at</c>/<c>first_cached_at</c> to a
/// fixed instant rather than relying on the real clock's push-order timing: back-to-back real
/// pushes in a fast test run can land in the same second (created_at/first_cached_at are
/// second-precision TEXT), so an assertion that only depends on push order would pass or fail
/// on which side of a second boundary either write happens to land — explicit, well-separated
/// instants make each assertion depend only on the resolution rule under test (SemVer
/// precedence, prerelease eligibility, or the uploaded-over-proxy tie-break).
/// </summary>
[Trait("Category", "Integration")]
public sealed class VersionPrecedenceReadSurfacesTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public VersionPrecedenceReadSurfacesTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    // ── helpers ────────────────────────────────────────────────────────────────

    private async Task<string> GetDefaultOrgIdAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("Default org not found.");
    }

    private async Task DisablePassthroughAsync(string orgId)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    private async Task RestorePassthroughAsync(string orgId)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 1 WHERE org_id = @orgId",
            new { orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }

    // Publishes a Cargo crate version via the real /cargo/api/v1/crates/new frame, matching
    // the wire format the Cargo CLI sends (u32 LE metadata length, metadata JSON, u32 LE crate
    // length, crate bytes).
    private static async Task PushCargoCrateAsync(HttpClient client, string name, string version)
    {
        byte[] crateBytes = [0x50, 0x4B, 0x03, 0x04];
        string metaJson = $"{{\"name\":\"{name}\",\"vers\":\"{version}\",\"deps\":[],\"features\":{{}},\"description\":\"test\"}}";
        byte[] metaEncoded = System.Text.Encoding.UTF8.GetBytes(metaJson);
        byte[] frame = new byte[4 + metaEncoded.Length + 4 + crateBytes.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)metaEncoded.Length);
        metaEncoded.CopyTo(frame, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            frame.AsSpan(4 + metaEncoded.Length), (uint)crateBytes.Length);
        crateBytes.CopyTo(frame, 4 + metaEncoded.Length + 4);
        var content = new ByteArrayContent(frame);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        var resp = await client.PutAsync("/cargo/api/v1/crates/new", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // Seeds a global-plane proxy entry (cache_artifact + tenant_artifact_access), matching the
    // real proxy first-fetch write path — same shape as ProxyVersionReadSurfacesTests.
    private async Task<string> SeedGlobalPlaneEntryAsync(
        string orgId, string ecosystem, string name, string version, string filename)
    {
        byte[] fakeBytes = [0x42, 0x43, 0x44, 0x45];
        string sha256 = Convert.ToHexString(SHA256.HashData(fakeBytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);

        await _factory.BlobStore.PutAsync(
            BlobKeys.StoreKey(blobKey), new MemoryStream(fakeBytes), CancellationToken.None);

        var recorder = _factory.Services.GetRequiredService<CacheAccessRecorder>();
        string? caId = await recorder.RecordAccessAsync(new CacheAccess(
            orgId, ecosystem, name, version, filename,
            Sha256: sha256, SizeBytes: fakeBytes.Length,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://upstream.example/{filename}"));

        await _factory.Services.GetRequiredService<PackageRepository>()
            .GetOrCreateAsync(orgId, ecosystem, name, name, isProxy: true, CancellationToken.None);

        return caId ?? throw new InvalidOperationException("CacheAccessRecorder did not return an id.");
    }

    // Stamps an uploaded version's created_at to a fixed instant, so resolution order depends
    // only on the rule under test, never on which wall-clock second either push happened to land in.
    private async Task SetUploadedCreatedAtAsync(string ecosystem, string name, string version, string ts)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE package_versions SET created_at = @ts
            WHERE version = @version
              AND package_id = (SELECT id FROM packages WHERE ecosystem = @ecosystem AND purl_name = @name)
            """,
            new { ts, version, ecosystem, name });
    }

    // Stamps a global-plane proxy entry's first_cached_at (projected as PackageVersion.CreatedAt).
    private async Task SetProxyCreatedAtAsync(string ecosystem, string name, string ts)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET first_cached_at = @ts WHERE ecosystem = @ecosystem AND name = @name",
            new { ts, ecosystem, name });
    }

    // ── Cargo: max_version resolves by SemVer precedence ───────────────────────

    /// <summary>
    /// Headline defect: a hotfix (1.0.1) published — and so created — after a major release
    /// (2.0.0) must not make the hotfix report as max_version. crates.io's max_version is
    /// highest-precedence, not most-recently-published.
    /// </summary>
    [Fact]
    public async Task CargoSearch_HotfixPublishedAfterMajor_MaxVersionIsHigherSemVer()
    {
        string name = $"vp-cargo-hf-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        await PushCargoCrateAsync(client, name, "2.0.0");
        await PushCargoCrateAsync(client, name, "1.0.1");
        // The hotfix is unambiguously newer by wall clock — SemVer precedence must still win.
        await SetUploadedCreatedAtAsync("cargo", name, "2.0.0", "2026-01-01T00:00:00Z");
        await SetUploadedCreatedAtAsync("cargo", name, "1.0.1", "2026-01-01T00:05:00Z");

        var resp = await client.GetAsync($"/cargo/api/v1/crates?q={name}&per_page=5");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var crate = doc.RootElement.GetProperty("crates").EnumerateArray()
            .First(c => string.Equals(c.GetProperty("name").GetString(), name, StringComparison.OrdinalIgnoreCase));

        Assert.Equal("2.0.0", crate.GetProperty("max_version").GetString());
    }

    /// <summary>
    /// crates.io's max_version (unlike max_stable_version, a separate field this endpoint does
    /// not emit) includes prereleases: the highest-precedence version wins even when it carries
    /// a prerelease label and even when the stable version was created more recently.
    /// </summary>
    [Fact]
    public async Task CargoSearch_MaxVersionIncludesPrerelease()
    {
        string name = $"vp-cargo-pre-{Guid.NewGuid():N}"[..20].ToLowerInvariant();
        string token = await _factory.CreateToken("push");
        using var client = _factory.CreateClientWithBearer(token);

        await PushCargoCrateAsync(client, name, "1.0.0");
        await PushCargoCrateAsync(client, name, "2.0.0-alpha.1");
        // The stable version is the newer one by wall clock — the prerelease must still win
        // on precedence, since max_version does not exclude prereleases.
        await SetUploadedCreatedAtAsync("cargo", name, "2.0.0-alpha.1", "2026-01-01T00:00:00Z");
        await SetUploadedCreatedAtAsync("cargo", name, "1.0.0", "2026-01-01T00:05:00Z");

        var resp = await client.GetAsync($"/cargo/api/v1/crates?q={name}&per_page=5");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var crate = doc.RootElement.GetProperty("crates").EnumerateArray()
            .First(c => string.Equals(c.GetProperty("name").GetString(), name, StringComparison.OrdinalIgnoreCase));

        Assert.Equal("2.0.0-alpha.1", crate.GetProperty("max_version").GetString());
    }

    // ── NuGet: search resolves by SemVer precedence ─────────────────────────────

    /// <summary>
    /// Headline defect: a hotfix (1.0.1) published — and so created — after a major release
    /// (2.0.0) must not make the hotfix report as the search result's 'version' field.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_HotfixPublishedAfterMajor_LatestIsHigherSemVer()
    {
        string id = $"vpnugethf{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "2.0.0");
        await _factory.PushNuGetPackage(id, "1.0.1");
        await SetUploadedCreatedAtAsync("nuget", id, "2.0.0", "2026-01-01T00:00:00Z");
        await SetUploadedCreatedAtAsync("nuget", id, "1.0.1", "2026-01-01T00:05:00Z");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/query?q={id}&take=10");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var package = doc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));

        Assert.Equal("2.0.0", package.GetProperty("version").GetString());
    }

    /// <summary>
    /// The Search Query Service's 'prerelease' request parameter (default false, per spec)
    /// controls both the reported 'latest' version and the 'versions' array: a stable version is
    /// preferred over a higher-precedence, more-recently-created prerelease by default, and the
    /// 'versions' array lists only stable versions until the caller opts in — nuget.org enforces
    /// this on the array too (NuGet.Client applies no client-side filter of its own and trusts
    /// the array verbatim, so a half-filtered array is client-visible: Visual Studio's Package
    /// Manager pre-selects whatever 'versions' array reports as newest).
    /// </summary>
    [Fact]
    public async Task NuGetSearch_PrereleaseParameter_ControlsEligibility()
    {
        string id = $"vpnugetpre{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        await _factory.PushNuGetPackage(id, "2.0.0-beta1");
        // The prerelease is the newer one by wall clock — the default request must still prefer
        // the stable version, and only the prerelease=true request may return the prerelease.
        await SetUploadedCreatedAtAsync("nuget", id, "1.0.0", "2026-01-01T00:00:00Z");
        await SetUploadedCreatedAtAsync("nuget", id, "2.0.0-beta1", "2026-01-01T00:05:00Z");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var defaultResp = await client.GetAsync($"/nuget/query?q={id}&take=10");
        Assert.Equal(HttpStatusCode.OK, defaultResp.StatusCode);
        using var defaultDoc = JsonDocument.Parse(await defaultResp.Content.ReadAsStringAsync());
        var defaultPackage = defaultDoc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("1.0.0", defaultPackage.GetProperty("version").GetString());
        var defaultVersions = defaultPackage.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("1.0.0", defaultVersions);
        Assert.DoesNotContain("2.0.0-beta1", defaultVersions);

        var prereleaseResp = await client.GetAsync($"/nuget/query?q={id}&take=10&prerelease=true");
        Assert.Equal(HttpStatusCode.OK, prereleaseResp.StatusCode);
        using var prereleaseDoc = JsonDocument.Parse(await prereleaseResp.Content.ReadAsStringAsync());
        var prereleasePackage = prereleaseDoc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("2.0.0-beta1", prereleasePackage.GetProperty("version").GetString());
        var prereleaseVersions = prereleasePackage.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("1.0.0", prereleaseVersions);
        Assert.Contains("2.0.0-beta1", prereleaseVersions);
    }

    /// <summary>
    /// A package whose only version is a prerelease is omitted from search results under the
    /// default (prerelease=false) request — including from totalHits — the same rule
    /// AutocompleteAsync already applies via its MatchesFilter/hasMatchingVersion checks, and the
    /// rule nuget.org itself applies. Opting into prerelease=true both counts and returns it.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_OnlyPrereleaseVersion_OmittedByDefault_IncludedWhenOptedIn()
    {
        string id = $"vpnugetonlypre{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0-beta1");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var defaultResp = await client.GetAsync($"/nuget/query?q={id}&take=10");
        Assert.Equal(HttpStatusCode.OK, defaultResp.StatusCode);
        using var defaultDoc = JsonDocument.Parse(await defaultResp.Content.ReadAsStringAsync());
        Assert.Equal(0, defaultDoc.RootElement.GetProperty("totalHits").GetInt32());
        var defaultResults = defaultDoc.RootElement.GetProperty("data").EnumerateArray().ToList();
        Assert.DoesNotContain(defaultResults, r =>
            string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));

        var prereleaseResp = await client.GetAsync($"/nuget/query?q={id}&take=10&prerelease=true");
        Assert.Equal(HttpStatusCode.OK, prereleaseResp.StatusCode);
        using var prereleaseDoc = JsonDocument.Parse(await prereleaseResp.Content.ReadAsStringAsync());
        Assert.Equal(1, prereleaseDoc.RootElement.GetProperty("totalHits").GetInt32());
        var prereleasePackage = prereleaseDoc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("1.0.0-beta1", prereleasePackage.GetProperty("version").GetString());
    }

    /// <summary>
    /// <c>?prerelease=</c> (an empty query value, which nuget.org accepts as "not set") must
    /// return 200, not 400: <c>[FromQuery] bool</c> fails ASP.NET Core's model binding on an
    /// empty string, and <c>[ApiController]</c> auto-400s that failure. <c>prerelease</c> is
    /// declared <c>bool?</c> precisely so an omitted-value shape still parses.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_EmptyPrereleaseQueryValue_ReturnsOk()
    {
        string id = $"vpnugetempty{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/query?q={id}&take=10&prerelease=");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var package = doc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));
        Assert.Equal("1.0.0", package.GetProperty("version").GetString());
    }

    /// <summary>
    /// A version string that fails to parse as SemVer must not throw and must not hide the
    /// rest of the package's versions: the parseable versions still resolve correctly and all
    /// versions (parseable or not) remain visible in the 'versions' array.
    ///
    /// The real publish path (<c>NuGetNupkgValidator</c>) rejects an unparseable version at
    /// push time, so this shape only reaches the DB via a pre-existing/legacy row or a direct
    /// migration — seeded here with <see cref="Dependably.Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync"/>
    /// to model that. Stamped as the most-recently-created row so a CreatedAt-only resolver
    /// would pick the malformed string outright.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_UnparseableVersion_DoesNotHideOtherVersions()
    {
        string id = $"vpnugetbad{Guid.NewGuid():N}"[..16].ToLowerInvariant();
        await _factory.PushNuGetPackage(id, "1.0.0");
        await _factory.PushNuGetPackage(id, "2.0.0");
        await SetUploadedCreatedAtAsync("nuget", id, "1.0.0", "2026-01-01T00:00:00Z");
        await SetUploadedCreatedAtAsync("nuget", id, "2.0.0", "2026-01-01T00:05:00Z");

        string orgId = await GetDefaultOrgIdAsync();
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        var pkg = await _factory.Services.GetRequiredService<PackageRepository>()
            .GetByPurlNameAsync(orgId, "nuget", id, CancellationToken.None);
        Assert.NotNull(pkg);
        await Dependably.Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync(
            db, pkg.Id, "not-a-version", $"pkg:nuget/{id}@not-a-version", blobKey: $"blob/{Guid.NewGuid():N}");
        // Most recently created of the three — a CreatedAt-only resolver would pick this
        // unparseable string outright as "latest".
        await SetUploadedCreatedAtAsync("nuget", id, "not-a-version", "2026-01-01T00:10:00Z");

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var resp = await client.GetAsync($"/nuget/query?q={id}&take=10");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var package = doc.RootElement.GetProperty("data").EnumerateArray()
            .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));

        Assert.Equal("2.0.0", package.GetProperty("version").GetString());

        var allVersions = package.GetProperty("versions").EnumerateArray()
            .Select(v => v.GetProperty("version").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("not-a-version", allVersions);
        Assert.Contains("1.0.0", allVersions);
        Assert.Contains("2.0.0", allVersions);
    }

    /// <summary>
    /// A genuine precedence tie between an uploaded version and a global-plane proxy version
    /// (same SemVer precedence, different raw strings — "1.0.0" vs "1.0" — so the exact-string
    /// dedup in <c>ListServeableVersionsAsync</c> does not collapse them) with identical
    /// CreatedAt must resolve to the uploaded (hosted) version, never the proxy one: a proxy
    /// CreatedAt is a global-plane timestamp that can predate this tenant's own fetch, so it is
    /// never trusted over a hosted publish on a tie. Pins the tie-break direction against a
    /// plausible wrong implementation that prefers proxy on a tie.
    /// </summary>
    [Fact]
    public async Task NuGetSearch_HostedVsProxyGenuineTie_ResolvesToHosted()
    {
        string defaultOrgId = await GetDefaultOrgIdAsync();
        await DisablePassthroughAsync(defaultOrgId);
        try
        {
            string id = $"vpnugettie{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            await _factory.PushNuGetPackage(id, "1.0.0");
            await SeedGlobalPlaneEntryAsync(defaultOrgId, "nuget", id, "1.0", $"{id}.1.0.nupkg");

            // Force an exact tie: both rows report the same CreatedAt instant.
            const string ts = "2026-01-01T00:00:00Z";
            await SetUploadedCreatedAtAsync("nuget", id, "1.0.0", ts);
            await SetProxyCreatedAtAsync("nuget", id, ts);

            string token = await _factory.CreateToken("pull");
            using var client = _factory.CreateClientWithBasic(token);

            var resp = await client.GetAsync($"/nuget/query?q={id}&take=10");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var package = doc.RootElement.GetProperty("data").EnumerateArray()
                .First(r => string.Equals(r.GetProperty("id").GetString(), id, StringComparison.OrdinalIgnoreCase));

            Assert.Equal("1.0.0", package.GetProperty("version").GetString());
        }
        finally
        {
            await RestorePassthroughAsync(defaultOrgId);
        }
    }
}
