using System.Buffers.Binary;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit coverage for <see cref="RpmController"/>. The controller is constructed
/// against real repositories + an in-memory blob store + a fresh SQLite schema, so each
/// test exercises the actual SQL paths in the controller. <c>RpmControllerServices</c>
/// isn't wired into <see cref="ControllerScenario"/> yet — building the bundle inline
/// keeps these tests independent of that broader infra refactor.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmControllerUnitTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private RpmController _controller = null!;
    private string _orgId = null!;
    private TokenRepository _tokens = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
                new { id = _orgId, slug = "acme-rpm" });
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, anonymous_pull) VALUES (@id, 1)",
                new { id = _orgId });
        }

        _tokens = new TokenRepository(_db);
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var orgs = new OrgRepository(_db);
        var repodata = new RpmRepodataService(_db);
        var svc = new RpmControllerServices(packages, _tokens, audit, orgs, new TieredBlobStorage(_blobs, _blobs), _db, repodata,
            new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db)));
        _controller = new RpmController(svc)
        {
            ControllerContext = BuildContext(_orgId),
        };
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
    }

    // ── Upload ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Upload_ValidRpm_WithBearerToken_StoresAndReturns201()
    {
        // The happy path: a syntactically-valid RPM uploaded with a Bearer token whose
        // OrgId matches the tenant binding. Drives the full insert pipeline:
        // packages → package_versions → rpm_metadata → rpm_repodata_state (dirty).
        var raw = await SeedUserTokenAsync(_orgId);
        var bytes = BuildRpm(name: "zlib", version: "1.2.11", release: "39.el9", arch: "x86_64");
        SetBody(bytes, $"Bearer {raw}");

        var result = await _controller.Upload(CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);
        Assert.Equal("pkg:rpm/zlib@1.2.11-39.el9?arch=x86_64",
            _controller.Response.Headers["X-Dependably-PURL"]);

        await using var conn = await _db.OpenAsync();
        var pv = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE version = @v",
            new { v = "1.2.11-39.el9" });
        Assert.Equal(1, pv);
        var rpm = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM rpm_metadata WHERE rpm_name = @n",
            new { n = "zlib" });
        Assert.Equal(1, rpm);
        var dirty = await conn.ExecuteScalarAsync<long>(
            "SELECT dirty FROM rpm_repodata_state WHERE org_id = @o AND arch = 'x86_64'",
            new { o = _orgId });
        Assert.Equal(1, dirty);
    }

    [Fact]
    public async Task Upload_NoToken_Returns401AndWwwAuthenticate()
    {
        var bytes = BuildRpm("foo", "1.0", "1", "x86_64");
        SetBody(bytes, authHeader: null);

        var result = await _controller.Upload(CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        Assert.Contains("Basic", _controller.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Upload_TokenForDifferentOrg_Returns401()
    {
        // Cross-tenant token presented: ResolveTokenAsync(orgId, ...) returns null when
        // the token's OrgId doesn't match — the controller treats that as no auth and
        // returns 401 with the WWW-Authenticate hint.
        var otherOrgId = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, 'other-rpm')",
                new { id = otherOrgId });
        }
        var raw = await SeedUserTokenAsync(otherOrgId);
        var bytes = BuildRpm("foo", "1.0", "1", "x86_64");
        SetBody(bytes, $"Bearer {raw}");

        var result = await _controller.Upload(CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Upload_TooSmall_Returns400_BeforeAnyParseAttempt()
    {
        // Body smaller than RpmArtifactValidator.MinimumValidSize is rejected at the
        // explicit size guard — no parse exception ever fires.
        var raw = await SeedUserTokenAsync(_orgId);
        SetBody(new byte[10], $"Bearer {raw}");

        var result = await _controller.Upload(CancellationToken.None);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("too small", bad.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Upload_InvalidRpmMagic_Returns400WithParserMessage()
    {
        // Body is large enough to pass the size gate but the parser rejects it for bad
        // lead-magic — the controller surfaces the RpmParseException message as 400.
        var raw = await SeedUserTokenAsync(_orgId);
        SetBody(new byte[256], $"Bearer {raw}");

        var result = await _controller.Upload(CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Upload_ExceedsTenantSizeCap_Returns413()
    {
        // The cap-resolver reads org_settings.max_upload_bytes_rpm first; here we set
        // a 50-byte ceiling so even a minimal valid RPM (~200+ bytes) trips it.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_upload_bytes_rpm = 50 WHERE org_id = @o",
                new { o = _orgId });
        }
        var raw = await SeedUserTokenAsync(_orgId);
        var bytes = BuildRpm("foo", "1.0", "1", "x86_64");
        SetBody(bytes, $"Bearer {raw}");

        var result = await _controller.Upload(CancellationToken.None);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(413, status.StatusCode);
    }

    [Fact]
    public async Task Upload_TwiceForSameVersion_KeepsSingleRow_AndUpsertsRpmMetadata()
    {
        // The second upload binds to the existing package_versions row via the
        // SELECT id check; rpm_metadata uses ON CONFLICT(package_version_id) DO UPDATE.
        var raw = await SeedUserTokenAsync(_orgId);
        var bytes = BuildRpm("zlib", "1.2.11", "39.el9", "x86_64");
        SetBody(bytes, $"Bearer {raw}");
        var first = await _controller.Upload(CancellationToken.None);
        Assert.Equal(201, ((StatusCodeResult)first).StatusCode);

        // Re-issue request — same body, same token. Set up a fresh response so headers
        // don't bleed.
        _controller.ControllerContext = BuildContext(_orgId);
        SetBody(bytes, $"Bearer {raw}");
        var second = await _controller.Upload(CancellationToken.None);

        Assert.Equal(201, ((StatusCodeResult)second).StatusCode);

        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE version = '1.2.11-39.el9'");
        Assert.Equal(1, count);
    }

    // ── Download ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Download_BadPath_Returns400()
    {
        // PathSafeValidator catches obvious traversal attempts.
        var result = await _controller.Download("../etc/passwd", CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Download_NonRpmExtension_Returns400()
    {
        // Even a path-safe filename is rejected unless it ends in .rpm.
        var result = await _controller.Download("not-an-rpm.txt", CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Download_AnonymousWhenPullDisabled_Returns401()
    {
        // Flip anonymous_pull off and confirm anonymous downloads get the 401 + Basic challenge.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @o",
                new { o = _orgId });
        }
        SetEmptyRequest();

        var result = await _controller.Download("zlib-1.2.11-39.el9.x86_64.rpm", CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        Assert.Contains("Basic", _controller.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Download_NoMatchingVersion_Returns404()
    {
        // anonymous_pull is on by default, no package seeded → FindVersionByBlobKeySuffix
        // returns null.
        SetEmptyRequest();

        var result = await _controller.Download("ghost-1.0.0-1.x86_64.rpm", CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_BlobMissing_Returns404()
    {
        // Seed a package_versions row whose blob_key doesn't resolve in the blob store —
        // controller must surface 404 instead of a 500 / NRE.
        const string filename = "zlib-1.2.11-39.el9.x86_64.rpm";
        await SeedPackageVersionAsync(filename);
        SetEmptyRequest();

        var result = await _controller.Download(filename, CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_BlobPresent_ReturnsFileResultWithRpmContentType()
    {
        // Round-trip: stash the bytes under the same blob_key we seeded the version with
        // and confirm the FileStreamResult carries the right content type + filename.
        const string filename = "zlib-1.2.11-39.el9.x86_64.rpm";
        var blobKey = await SeedPackageVersionAsync(filename);
        await _blobs.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(new byte[] { 0xED, 0xAB }), CancellationToken.None);
        SetEmptyRequest();

        var result = await _controller.Download(filename, CancellationToken.None);

        var file = Assert.IsAssignableFrom<FileResult>(result);
        Assert.Equal("application/x-rpm", file.ContentType);
        Assert.Equal(filename, file.FileDownloadName);
    }

    // ── Repodata ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_BadPath_Returns400()
    {
        var result = await _controller.Repodata("..", CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Repodata_AnonymousWhenPullDisabled_Returns401()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @o",
                new { o = _orgId });
        }
        SetEmptyRequest();

        var result = await _controller.Repodata("repomd.xml", CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Repodata_UnknownFile_Returns404()
    {
        // Anything outside repomd.xml / primary.xml.gz is not served (yet).
        SetEmptyRequest();
        var result = await _controller.Repodata("filelists.xml.gz", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Test helpers ───────────────────────────────────────────────────────────

    private static ControllerContext BuildContext(string orgId)
    {
        var http = new DefaultHttpContext();
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "acme-rpm");
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme-rpm.example.test");
        return new ControllerContext { HttpContext = http };
    }

    private void SetBody(byte[] bytes, string? authHeader)
    {
        _controller.ControllerContext = BuildContext(_orgId);
        var req = _controller.Request;
        req.Body = new MemoryStream(bytes);
        req.ContentLength = bytes.Length;
        if (authHeader is not null) req.Headers.Authorization = authHeader;
    }

    private void SetEmptyRequest()
    {
        _controller.ControllerContext = BuildContext(_orgId);
    }

    private async Task<string> SeedUserTokenAsync(string orgId)
    {
        var raw = $"raw-{Guid.NewGuid():N}";
        var hash = TokenRepository.HashToken(raw);
        var userId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES (@id, @t, @e, 'x', 'owner')",
            new { id = userId, t = orgId, e = $"{userId}@test" });
        await conn.ExecuteAsync("""
            INSERT INTO user_tokens (id, org_id, user_id, token_hash, capabilities, created_at)
            VALUES (@id, @o, @u, @h, @c, @ts)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                o = orgId,
                u = userId,
                h = hash,
                c = """["publish:rpm"]""",
                ts = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            });
        return raw;
    }

    private async Task<string> SeedPackageVersionAsync(string filename)
    {
        // Builds the same package + version a real upload would, so the controller's
        // FindVersionByBlobKeySuffixAsync(file=...) hits a real row.
        var pkgId = Guid.NewGuid().ToString("N");
        var verId = Guid.NewGuid().ToString("N");
        var blobKey = BlobKeys.Hosted(_orgId, "rpm", "zlib", "1.2.11-39.el9", filename);
        var purl = $"pkg:rpm/zlib@1.2.11-39.el9?arch=x86_64";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@id, @o, 'rpm', 'zlib', 'zlib', 0)
            """, new { id = pkgId, o = _orgId });
        await conn.ExecuteAsync("""
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @p, '1.2.11-39.el9', @purl, @bk, @fn, 16, 'deadbeef', 'uploaded')
            """, new { id = verId, p = pkgId, purl, bk = blobKey, fn = filename });
        return blobKey;
    }

    // ── Synthetic RPM bytes ────────────────────────────────────────────────────

    private static byte[] BuildRpm(string name, string version, string release, string arch)
    {
        var tags = new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, name),
            RpmTagWrite.String(1001, version),
            RpmTagWrite.String(1002, release),
            RpmTagWrite.String(1022, arch),
            RpmTagWrite.Int32(1003, 0),
        };
        var lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = 3;
        var sig = BuildHeaderIntro(0, 0);
        var sigEnd = 96 + sig.Length;
        var pad = new byte[(8 - (sigEnd % 8)) % 8];
        var (index, store) = BuildHeader(tags);
        var intro = BuildHeaderIntro(tags.Count, store.Length);
        return [..lead, ..sig, ..pad, ..intro, ..index, ..store];
    }

    private static byte[] BuildHeaderIntro(int nindex, int hsize)
    {
        var b = new byte[16];
        b[0] = 0x8E; b[1] = 0xAD; b[2] = 0xE8; b[3] = 0x01;
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), nindex);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), hsize);
        return b;
    }

    private static (byte[] Index, byte[] Store) BuildHeader(List<RpmTagWrite> tags)
    {
        var index = new List<byte>();
        var store = new List<byte>();
        foreach (var t in tags)
        {
            var offset = store.Count;
            var b = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(0, 4), t.Tag);
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(4, 4), t.Type);
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), offset);
            BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), t.Count);
            index.AddRange(b);
            store.AddRange(t.Bytes);
        }
        return (index.ToArray(), store.ToArray());
    }

    private sealed record RpmTagWrite(int Tag, int Type, int Count, byte[] Bytes)
    {
        public static RpmTagWrite String(int tag, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var withNul = new byte[bytes.Length + 1];
            Array.Copy(bytes, withNul, bytes.Length);
            return new RpmTagWrite(tag, 6, 1, withNul);
        }

        public static RpmTagWrite Int32(int tag, int value)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(bytes, value);
            return new RpmTagWrite(tag, 4, 1, bytes);
        }
    }
}
