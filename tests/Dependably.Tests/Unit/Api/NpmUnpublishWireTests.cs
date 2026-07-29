using System.Text;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Api.NpmProtocol;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage for the modern npm per-version unpublish wire sequence. Real npm resolves
/// <c>npm unpublish pkg@version</c> as GET packument (reads <c>_rev</c>) → PUT the pruned packument
/// to <c>/npm/{pkg}/-rev/{_rev}</c> → DELETE <c>/npm/{pkg}/-/{tarball}/-rev/{_rev}</c>. Before this
/// fix the packument advertised no <c>_rev</c>, so the CLI resolved <c>undefined</c>, PUT to
/// <c>/-rev/undefined</c> (404), yet exited 0 — the version was reported gone while it still listed.
///
/// These tests pin: the packument now emits a synthetic <c>_rev</c>; the rev-PUT prune deletes the
/// stored uploaded versions absent from the body's keep-set (leaving proxy versions and kept
/// versions intact); an unresolvable rev fails loud instead of silently no-opping; an empty
/// keep-set is refused rather than mass-deleting; and the tarball DELETE-with-rev is idempotent.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmUnpublishWireTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = "npm-unpub-org" });
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, anonymous_pull, proxy_passthrough_enabled) VALUES (@id, 1, 0)",
            new { id = _orgId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Defect: the packument advertised no _rev ─────────────────────────────────

    [Fact]
    public void BuildNpmMetadata_EmitsSyntheticRev_ShapedCountDashHex()
    {
        var pkg = new Package { Id = "p1", Name = "left-pad", OrgId = _orgId, Ecosystem = "npm" };
        var versions = new List<PackageVersion>
        {
            Version("1.0.0"),
            Version("1.1.0"),
        };

        var meta = NpmPackumentHandler.BuildNpmMetadata(
            "https://host/npm/tarballs", pkg, versions, persistedTags: null,
            new OrgSettings(), new Dictionary<string, VulnGateSignals>(), _clock.GetUtcNow());

        // Old code omitted _rev entirely — the CLI would resolve "undefined".
        string? rev = meta["_rev"]?.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(rev), "packument must advertise a _rev for npm unpublish to resolve");
        Assert.Matches(@"^\d+-[0-9a-f]{12}$", rev);
        Assert.StartsWith("2-", rev); // two versions in the set
    }

    // ── Defect: rev-PUT prune route was unimplemented (silent no-op) ─────────────

    [Fact]
    public async Task RevPutPrune_MixedOrigins_RemovesUploadedNotInKeepSet_KeepsProxyAndKept()
    {
        await SeedPackageAsync();
        await SeedVersionAsync("1.0.0", "uploaded");
        await SeedVersionAsync("1.1.0", "uploaded");
        await SeedVersionAsync("1.2.0", "uploaded");
        await SeedVersionAsync("2.0.0", "proxy"); // cannot be unpublished — must survive
        string token = await SeedTokenAsync();

        var handler = BuildHandler();

        // Body keeps only 1.1.0 → 1.0.0 and 1.2.0 (both uploaded) are pruned in one fan-out call;
        // the proxy version 2.0.0 is absent from the keep-set but is not an unpublishable origin.
        var http = BuildContext(token, PackumentKeeping("1.1.0"));
        var result = await handler.UnpublishRevPutAsync(http, _orgId, "left-pad", "3-abcabcabcabc", CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        var remaining = await RemainingVersionsAsync();
        Assert.DoesNotContain("1.0.0", remaining);
        Assert.DoesNotContain("1.2.0", remaining);
        Assert.Contains("1.1.0", remaining);
        Assert.Contains("2.0.0", remaining); // proxy version untouched
    }

    [Fact]
    public async Task RevPutPrune_UnresolvableRev_FailsLoudWith409()
    {
        await SeedPackageAsync();
        await SeedVersionAsync("1.0.0", "uploaded");
        await SeedVersionAsync("1.1.0", "uploaded");
        string token = await SeedTokenAsync();

        var handler = BuildHandler();
        var http = BuildContext(token, PackumentKeeping("1.1.0"));
        var result = await handler.UnpublishRevPutAsync(http, _orgId, "left-pad", "undefined", CancellationToken.None);

        var obj = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status409Conflict, obj.StatusCode);
        // Nothing pruned — the loud failure must not have deleted anything.
        var remaining = await RemainingVersionsAsync();
        Assert.Contains("1.0.0", remaining);
        Assert.Contains("1.1.0", remaining);
    }

    [Fact]
    public async Task RevPutPrune_EmptyKeepSet_Refused_DoesNotMassDelete()
    {
        await SeedPackageAsync();
        await SeedVersionAsync("1.0.0", "uploaded");
        await SeedVersionAsync("1.1.0", "uploaded");
        string token = await SeedTokenAsync();

        var handler = BuildHandler();
        var http = BuildContext(token, "{\"name\":\"left-pad\",\"versions\":{}}");
        var result = await handler.UnpublishRevPutAsync(http, _orgId, "left-pad", "2-abcabcabcabc", CancellationToken.None);

        Assert.IsType<UnprocessableEntityObjectResult>(result);
        var remaining = await RemainingVersionsAsync();
        Assert.Contains("1.0.0", remaining);
        Assert.Contains("1.1.0", remaining);
    }

    // ── Defect: the tarball DELETE-with-rev step was unrouted ────────────────────

    [Fact]
    public async Task DeleteTarballWithRev_AfterPrune_IsIdempotentOk()
    {
        await SeedPackageAsync();
        await SeedVersionAsync("1.1.0", "uploaded");
        string token = await SeedTokenAsync();

        var handler = BuildHandler();

        // The version was already pruned by the rev-PUT step (simulate: it is simply absent).
        var http = BuildContext(token, body: null);
        var result = await handler.DeleteTarballWithRevAsync(
            http, _orgId, "left-pad", "left-pad-9.9.9.tgz", "5-abcabcabcabc", CancellationToken.None);

        Assert.IsType<OkResult>(result); // absent version → idempotent success, not 404/500
        Assert.Contains("1.1.0", await RemainingVersionsAsync()); // unrelated version untouched
    }

    [Fact]
    public async Task DeleteTarballWithRev_VersionStillPresent_RemovesIt()
    {
        await SeedPackageAsync();
        await SeedVersionAsync("1.0.0", "uploaded");
        await SeedVersionAsync("1.1.0", "uploaded");
        string token = await SeedTokenAsync();

        var handler = BuildHandler();
        var http = BuildContext(token, body: null);
        var result = await handler.DeleteTarballWithRevAsync(
            http, _orgId, "left-pad", "left-pad-1.0.0.tgz", "3-abcabcabcabc", CancellationToken.None);

        Assert.IsType<OkResult>(result);
        var remaining = await RemainingVersionsAsync();
        Assert.DoesNotContain("1.0.0", remaining);
        Assert.Contains("1.1.0", remaining);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private PackageVersion Version(string v) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        Version = v,
        Purl = PurlNormalizer.Npm("left-pad", v),
        BlobKey = $"registry/left-pad-{v}.tgz",
        Filename = $"left-pad-{v}.tgz",
        Origin = "uploaded",
        CreatedAt = _clock.GetUtcNow(),
    };

    private static string PackumentKeeping(params string[] keep)
    {
        var versions = new JsonObject();
        foreach (string v in keep)
        {
            versions[v] = new JsonObject { ["name"] = "left-pad", ["version"] = v };
        }
        return new JsonObject { ["name"] = "left-pad", ["versions"] = versions }.ToJsonString();
    }

    private async Task SeedPackageAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES ('pkg-lp', @o, 'npm', 'left-pad', 'left-pad', 0)
            """, new { o = _orgId });
    }

    private async Task SeedVersionAsync(string version, string origin)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin, filename, created_at)
            VALUES (@id, 'pkg-lp', @v, @purl, @bk, @origin, @fn, @ts)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                v = version,
                purl = PurlNormalizer.Npm("left-pad", version),
                bk = $"registry/left-pad-{version}.tgz",
                origin,
                fn = $"left-pad-{version}.tgz",
                ts = _clock.GetUtcNow().ToUtcIso(),
            });
    }

    private async Task<string> SeedTokenAsync()
    {
        string raw = TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ('u1', @o, 'pub@npm-unpub-org', 'x', 'owner')",
            new { o = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities)
            VALUES (@id, @o, 'u1', @hash, '["npm:yank"]')
            """,
            new { id = Guid.NewGuid().ToString("N"), o = _orgId, hash });
        return raw;
    }

    private async Task<HashSet<string>> RemainingVersionsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<string>(
            "SELECT version FROM package_versions WHERE package_id = 'pkg-lp'");
        return rows.ToHashSet();
    }

    private DefaultHttpContext BuildContext(string token, string? body)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "npm-unpub-org");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("host.example.test");
        http.Request.Headers.Authorization = "Bearer " + token;
        if (body is not null)
        {
            http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        }
        return http;
    }

    private NpmPublishHandler BuildHandler()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}"),
            })
            .Build();

        var orgs = new OrgRepository(_db);
        var packages = new PackageRepository(_db);
        var tokens = new TokenRepository(_db, _clock);
        var audit = new AuditRepository(_db);
        var claims = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(config));
        var licenses = new LicenseRepository(_db, _clock, TestNormalizers.License(_db));
        var distTags = new NpmDistTagRepository(_db, _clock);
        var invalidation = TestMetadataInvalidation.Coordinator();
        var uploadLimits = Substitute.For<IUploadLimitResolver>();
        var publish = Substitute.For<Dependably.Infrastructure.Publish.IPackagePublishService>();

        return new NpmPublishHandler(
            orgs, packages, tokens, audit, _blobs, publish, claims, licenses, uploadLimits,
            distTags, invalidation, TestEdgeMode.DisabledPublishGuard(), config["PROXY_STAGING_PATH"]!);
    }
}
