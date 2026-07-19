using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit coverage for <see cref="MavenController"/>. The controller isn't wired into
/// <c>ControllerScenario</c> (Maven has its own multi-file shape with maven_version_files),
/// so we stand it up by hand against the in-memory metadata store + blob store. Each test
/// gets a fresh fixture, an org + user seeded, then constructs the controller against the
/// real repositories.
///
/// Coverage targets:
///  - GET artifact happy path (from a pre-seeded maven_version_files row)
///  - GET checksum sidecar (stored hex + on-the-fly sha512 fallback)
///  - GET metadata.xml + its sidecar
///  - GET unknown coords → 404
///  - GET on invalid path / empty path / unparseable segments
///  - GET anonymous-pull denied → 401 with WWW-Authenticate
///  - PUT happy path (primary jar) → 201 + maven_version_files row
///  - PUT for a metadata file → 201 (acknowledged + discarded)
///  - PUT sidecar matching primary checksum → 201
///  - PUT sidecar mismatched → 400
///  - PUT empty path → 400
///  - PUT unparseable path → 400
///  - PUT artifact missing version segment → 400
///  - PUT with no token → 401
///  - PUT with cross-tenant token → 401
///  - PUT exceeding per-tenant Maven size cap → 413
///  - PUT with path-traversal segment → 400 (PathSafeValidator)
/// </summary>
[Trait("Category", "Unit")]
public sealed class MavenControllerUnitTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    private string _orgId = null!;
    private string _otherOrgId = null!;
    private string _userId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, _clock);
        _audit = new AuditRepository(_db);
        _packages = new PackageRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
        _otherOrgId = await OrgSeeder.InsertAsync(_db, "other");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "owner@acme.test", "owner");

        // org_settings has anonymous_pull = 0 by default. Flip on the cases where we want it.
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── helpers ─────────────────────────────────────────────────────────────

    private MavenController BuildController(string? authHeader = null, bool authenticated = true)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("acme.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "acme");

        if (authenticated)
        {
            http.User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, _userId),
                    new Claim("sub", _userId),
                    new Claim("org_id", _orgId),
                    new Claim("tid", _orgId),
                    new Claim("role", "owner"),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"));
        }

        if (authHeader is not null)
        {
            http.Request.Headers.Authorization = authHeader;
        }

        var svc = new MavenControllerServices(
            Packages: _packages,
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            Blobs: _blobs,
            Db: _db,
            Upstream: null!,  // not exercised by unit tests — proxy fallback requires network
            Config: null!,
            // ProxyFetch is only reached on the proxy-miss path, which short-circuits to 404
            // here because Upstream is null. BlockGate runs on every cache hit, so it's real.
            ProxyFetch: null!,
            BlockGate: Dependably.Tests.Infrastructure.TestBlockGate.Create(_db, _clock),
            ReservedNamespaces: new ReservedNamespaceService(
                _db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), _clock),
            // Real resolver over an empty registry list — these tests exercise publish/auth
            // paths, not proxy fetches.
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, _clock, Dependably.Tests.Infrastructure.TestEnvelope.Unconfigured())),
            MetadataCache: new Dependably.Infrastructure.Caching.RenderedResponseCache<Dependably.Infrastructure.Caching.MavenMetadataKey>(
                new Microsoft.Extensions.Caching.Memory.MemoryCache(
                    new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 }),
                Dependably.Infrastructure.Caching.MetadataCacheKeys.MavenMetadata),
            CacheOptions: new Dependably.Infrastructure.RenderedMetadataCacheOptions(
                TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5)),
            Log: Microsoft.Extensions.Logging.Abstractions.NullLogger<MavenController>.Instance,
            CacheArtifacts: new CacheArtifactRepository(_db),
            TenantAccess: new TenantArtifactAccessRepository(_db),
            Time: _clock,
            CacheRecorder: new CacheAccessRecorder(
                new CacheArtifactRepository(_db),
                new TenantArtifactAccessRepository(_db),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<CacheAccessRecorder>.Instance,
                _clock),
            // No Maven trust anchors configured — IsConfiguredForAsync returns false, provenance skipped.
            MavenProvenance: new Dependably.Protocol.Provenance.MavenProvenanceVerifier(
                new Dependably.Tests.Infrastructure.StubPerOrgTrustAnchorStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenProvenanceVerifier>.Instance),
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            Staging: new Dependably.Infrastructure.StagingOptions(System.IO.Path.GetTempPath(), 0),
            Licenses: new LicenseRepository(_db, _clock, TestNormalizers.License(_db)));

        return new MavenController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private async Task<List<string>> HostedKeysAsync()
    {
        var keys = new List<string>();
        await foreach (var blob in _blobs.ListAsync("hosted/"))
        {
            keys.Add(blob.Key);
        }
        return keys;
    }

    private async Task<string> IssueTokenAsync(string orgId, string userId)
    {
        // Capabilities aren't enforced inside the controller body — the [RequireCapability]
        // attribute is filter-level and not exercised when invoking the action method
        // directly. We still set a JSON array for realism.
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            orgId, userId, """["publish:maven","read:metadata"]""", expiresAt: null);
        return raw;
    }

    private async Task<string> IssueReadArtifactTokenAsync(string orgId, string userId)
    {
        // Issues a token carrying read:artifact so the origin-based download gate allows
        // access to uploaded artifacts (origin='uploaded' requires this capability).
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            orgId, userId, """["read:artifact","read:metadata"]""", expiresAt: null);
        return raw;
    }

    private async Task<(string pkgId, string verId, string blobKey)> SeedMavenArtifactAsync(
        string groupId, string artifactId, string version, byte[] bytes)
    {
        string purlName = $"{groupId}:{artifactId}";
        string filename = $"{artifactId}-{version}.jar";
        string blobKey = BlobKeys.Hosted(_orgId, "maven", groupId.Replace('.', '/') + "/" + artifactId, version, filename);

        await _blobs.PutAsync(blobKey, new MemoryStream(bytes), CancellationToken.None);

        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        string verId = Guid.NewGuid().ToString("N");
        string fileId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        // Reuse the packages row if it already exists for this (org, ecosystem, purl_name) —
        // the UNIQUE constraint forbids a second insert and tests can seed multiple versions
        // of the same artifact (e.g. for maven-metadata.xml).
        string? existingPkgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM packages WHERE org_id = @org AND ecosystem = 'maven' AND purl_name = @purl",
            new { org = _orgId, purl = purlName });
        string pkgId = existingPkgId ?? Guid.NewGuid().ToString("N");
        if (existingPkgId is null)
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @org, 'maven', @name, @purl, 0)",
                new { id = pkgId, org = _orgId, name = purlName, purl = purlName });
        }
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkg, @ver, @purl, @blobKey, @filename, @size, @sha256, 'uploaded')
            """,
            new
            {
                id = verId,
                pkg = pkgId,
                ver = version,
                purl = $"pkg:maven/{groupId}/{artifactId}@{version}",
                blobKey,
                filename,
                size = (long)bytes.Length,
                sha256,
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pv, @filename, NULL, 'jar', @blobKey, @size, @sha256, @sha1, @md5, 'uploaded')
            """,
            new
            {
                id = fileId,
                pv = verId,
                filename,
                blobKey,
                size = (long)bytes.Length,
                sha256,
                sha1,
                md5,
            });

        return (pkgId, verId, blobKey);
    }

    // Seeds one hosted maven_version_files row under a shared SNAPSHOT package_versions row —
    // reuses the version row across calls so a test can seed several timestamped build files
    // (jar + pom, or multiple builds) under one SNAPSHOT version, the way a real `mvn deploy`
    // publishes a multi-file build.
    private async Task<string> SeedMavenSnapshotFileAsync(
        string groupId, string artifactId, string version, string filename, string extension, string? classifier)
    {
        string purlName = $"{groupId}:{artifactId}";
        byte[] bytes = Encoding.UTF8.GetBytes(filename);
        string blobKey = BlobKeys.Hosted(_orgId, "maven", groupId.Replace('.', '/') + "/" + artifactId, version, filename);
        await _blobs.PutAsync(blobKey, new MemoryStream(bytes), CancellationToken.None);

        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        await using var conn = await _db.OpenAsync();
        string? existingPkgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM packages WHERE org_id = @org AND ecosystem = 'maven' AND purl_name = @purl",
            new { org = _orgId, purl = purlName });
        string pkgId = existingPkgId ?? Guid.NewGuid().ToString("N");
        if (existingPkgId is null)
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @org, 'maven', @name, @purl, 0)",
                new { id = pkgId, org = _orgId, name = purlName, purl = purlName });
        }

        string? existingVerId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM package_versions WHERE package_id = @pkg AND version = @ver",
            new { pkg = pkgId, ver = version });
        string verId = existingVerId ?? Guid.NewGuid().ToString("N");
        if (existingVerId is null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
                VALUES (@id, @pkg, @ver, @purl, @blobKey, @filename, @size, @sha256, 'uploaded')
                """,
                new
                {
                    id = verId,
                    pkg = pkgId,
                    ver = version,
                    purl = $"pkg:maven/{groupId}/{artifactId}@{version}",
                    blobKey,
                    filename,
                    size = (long)bytes.Length,
                    sha256,
                });
        }

        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pv, @filename, @classifier, @extension, @blobKey, @size, @sha256, @sha1, @md5, 'uploaded')
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pv = verId,
                filename,
                classifier,
                extension,
                blobKey,
                size = (long)bytes.Length,
                sha256,
                sha1,
                md5,
            });

        return verId;
    }

    // Seeds one proxied Maven version onto the shared cache plane (cache_artifact +
    // tenant_artifact_access) with no package_versions row — where every current Maven proxy
    // fetch lands, and where the package_versions -> cache_artifact backfill leaves an upgraded
    // deployment's proxied versions. CacheAccessRecorder stamps first_cached_at from the
    // injected clock, so seeding several versions without advancing the frozen clock reproduces
    // the backfill's single shared timestamp across every row exactly.
    private async Task SeedMavenCachePlaneVersionAsync(string groupId, string artifactId, string version)
    {
        string purlName = $"{groupId}:{artifactId}";
        string filename = $"{artifactId}-{version}.jar";
        byte[] bytes = Encoding.UTF8.GetBytes(filename);
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.Proxy(sha256);
        await _blobs.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes), CancellationToken.None);

        var recorder = new CacheAccessRecorder(
            new CacheArtifactRepository(_db),
            new TenantArtifactAccessRepository(_db),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<CacheAccessRecorder>.Instance,
            _clock);
        string? id = await recorder.RecordAccessAsync(new CacheAccess(
            _orgId, "maven", purlName, version, filename,
            Sha256: sha256, SizeBytes: bytes.Length,
            BlobKey: $"{blobKey}/{filename}",
            UpstreamUrl: $"https://repo.example/{filename}"));
        Assert.NotNull(id);

        await _packages.GetOrCreateAsync(_orgId, "maven", purlName, purlName, isProxy: true, CancellationToken.None);
    }

    // Asserts the seeded cache-plane rows really do share one first_cached_at — the premise the
    // tie-order tests rest on. Without this the tests could pass for the wrong reason (distinct
    // timestamps ordering the versions correctly on their own).
    private async Task AssertCachePlaneTimestampsTiedAsync(string purlName, int expectedVersions)
    {
        await using var conn = await _db.OpenAsync();
        var stamps = (await conn.QueryAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE ecosystem = 'maven' AND name = @purlName",
            new { purlName })).ToList();

        Assert.Equal(expectedVersions, stamps.Count);
        Assert.Single(stamps.Distinct(StringComparer.Ordinal));
    }

    // Reads the <versioning> element of a served artifact-level maven-metadata.xml.
    private static async Task<XElement> ServedVersioningAsync(MavenController ctl, string path)
    {
        var content = Assert.IsType<ContentResult>(await ctl.Download(path, CancellationToken.None));
        return XDocument.Parse(content.Content!).Root!.Element("versioning")!;
    }

    // Seeds a proxy-cached Maven artifact (origin='proxy'). Use this for tests that exercise
    // behavior other than origin-based auth (checksums, block gate, metadata, HEAD) so they
    // remain servable under AnonymousPull without a token — uploaded artifacts require a token
    // even when AnonymousPull is enabled.
    private Task<(string pkgId, string verId, string blobKey)> SeedMavenProxyArtifactAsync(
        string groupId, string artifactId, string version, byte[] bytes)
        => SeedMavenProxyArtifactForOrgAsync(_orgId, groupId, artifactId, version, bytes);

    // Same seed, against an arbitrary org — lets a test place the identical coordinate in two
    // tenants and assert the serve path never crosses between them.
    private async Task<(string pkgId, string verId, string blobKey)> SeedMavenProxyArtifactForOrgAsync(
        string orgId, string groupId, string artifactId, string version, byte[] bytes)
    {
        string purlName = $"{groupId}:{artifactId}";
        string filename = $"{artifactId}-{version}.jar";
        string blobKey = BlobKeys.Hosted(orgId, "maven", groupId.Replace('.', '/') + "/" + artifactId, version, filename);

        await _blobs.PutAsync(blobKey, new MemoryStream(bytes), CancellationToken.None);

        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        string md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();

        string verId = Guid.NewGuid().ToString("N");
        string fileId = Guid.NewGuid().ToString("N");

        await using var conn = await _db.OpenAsync();
        string? existingPkgId = await conn.ExecuteScalarAsync<string?>(
            "SELECT id FROM packages WHERE org_id = @org AND ecosystem = 'maven' AND purl_name = @purl",
            new { org = orgId, purl = purlName });
        string pkgId = existingPkgId ?? Guid.NewGuid().ToString("N");
        if (existingPkgId is null)
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES (@id, @org, 'maven', @name, @purl, 1)",
                new { id = pkgId, org = orgId, name = purlName, purl = purlName });
        }
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, checksum_sha256, origin)
            VALUES (@id, @pkg, @ver, @purl, @blobKey, @filename, @size, @sha256, 'proxy')
            """,
            new
            {
                id = verId,
                pkg = pkgId,
                ver = version,
                purl = $"pkg:maven/{groupId}/{artifactId}@{version}",
                blobKey,
                filename,
                size = (long)bytes.Length,
                sha256,
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO maven_version_files
                (id, package_version_id, filename, classifier, extension, blob_key, size_bytes,
                 checksum_sha256, checksum_sha1, checksum_md5, origin)
            VALUES (@id, @pv, @filename, NULL, 'jar', @blobKey, @size, @sha256, @sha1, @md5, 'proxy')
            """,
            new
            {
                id = fileId,
                pv = verId,
                filename,
                blobKey,
                size = (long)bytes.Length,
                sha256,
                sha1,
                md5,
            });

        return (pkgId, verId, blobKey);
    }

    private async Task SetMaxUploadMavenAsync(long bytes)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_upload_bytes_maven = @bytes WHERE org_id = @org",
            new { bytes, org = _orgId });
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @flag WHERE org_id = @org",
            new { flag = enabled ? 1 : 0, org = _orgId });
    }

    // ── GET / Download ──────────────────────────────────────────────────────

    [Fact]
    public async Task Download_HappyPath_ReturnsFile()
    {
        // Uploaded artifacts require a token carrying read:artifact regardless of AnonymousPull.
        // Use a proxy-cached artifact here so the test remains focused on the file-serving path,
        // not the origin-auth gate (which has its own dedicated tests below).
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("jar-content");
        await SeedMavenProxyArtifactAsync("com.example", "mylib", "1.0", bytes);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/mylib/1.0/mylib-1.0.jar", CancellationToken.None);

        var file = Assert.IsType<FileStreamResult>(result);
        Assert.Equal("application/java-archive", file.ContentType);
        Assert.Equal("mylib-1.0.jar", file.FileDownloadName);
        file.FileStream.Dispose();
    }

    [Fact]
    public async Task Download_EmptyPath_Returns404()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        var result = await ctl.Download("", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_UnparseablePath_Returns400()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        // "too/short" has only 2 segments — MavenPathParser.Parse returns null.
        var result = await ctl.Download("too/short", CancellationToken.None);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("Invalid", bad.Value!.ToString()!);
    }

    [Fact]
    public async Task Download_AnonymousPullDisabled_Returns401()
    {
        // Default: anonymous_pull = 0 and no auth header → controller returns 401 with
        // WWW-Authenticate: Basic, the realm Maven clients expect to prompt creds for.
        var ctl = BuildController();
        var result = await ctl.Download("com/example/mylib/1.0/mylib-1.0.jar", CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        Assert.Contains("Basic", ctl.Response.Headers.WWWAuthenticate.ToString());
    }

    // ── Origin-based download auth (uploaded artifacts respect AnonymousPull) ──

    [Fact]
    public async Task Download_UploadedArtifact_AnonymousPullOn_AnonRequest_Returns200()
    {
        // AnonymousPull=true: anonymous callers may download uploaded artifacts, mirroring
        // proxy-cached artifact behavior. Gate on token capability only when a token is present.
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("private-jar");
        await SeedMavenArtifactAsync("com.example", "anonpull", "1.0", bytes);

        var ctl = BuildController(authenticated: false);
        var result = await ctl.Download("com/example/anonpull/1.0/anonpull-1.0.jar", CancellationToken.None);

        Assert.IsType<FileStreamResult>(result).FileStream.Dispose();
    }

    [Fact]
    public async Task Download_UploadedArtifact_AnonymousPullOff_AnonRequest_Returns401()
    {
        // AnonymousPull=false (default): anonymous callers must not receive uploaded artifacts.
        byte[] bytes = Encoding.UTF8.GetBytes("private-jar-off");
        await SeedMavenArtifactAsync("com.example", "anonpulloff", "1.0", bytes);

        var ctl = BuildController(authenticated: false);
        var result = await ctl.Download("com/example/anonpulloff/1.0/anonpulloff-1.0.jar", CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        Assert.Contains("Basic", ctl.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Download_UploadedArtifact_WithReadArtifactToken_Returns200()
    {
        // A token carrying read:artifact satisfies the origin gate and the file is served.
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("private-jar-content");
        await SeedMavenArtifactAsync("com.example", "private", "1.0", bytes);

        string raw = await IssueReadArtifactTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        var result = await ctl.Download("com/example/private/1.0/private-1.0.jar", CancellationToken.None);

        Assert.IsType<FileStreamResult>(result).FileStream.Dispose();
    }

    [Fact]
    public async Task Download_UploadedArtifact_TokenWithoutReadArtifact_Returns403()
    {
        // A token missing read:artifact hits the Forbid branch of the origin gate, even when
        // AnonymousPull is on — capability is still enforced for authenticated callers.
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("private-jar-no-cap");
        await SeedMavenArtifactAsync("com.example", "private2", "1.0", bytes);

        // This token has read:metadata but not read:artifact.
        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        var result = await ctl.Download("com/example/private2/1.0/private2-1.0.jar", CancellationToken.None);

        // ForbidResult from token.HasCapability(ReadArtifact) == false.
        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Download_ProxyArtifact_AnonymousPullOn_AnonRequest_Returns200()
    {
        // Proxy-cached artifacts remain freely accessible under AnonymousPull — the origin
        // gate applies only to uploaded artifacts.
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("proxy-jar");
        await SeedMavenProxyArtifactAsync("com.example", "proxied", "1.0", bytes);

        var ctl = BuildController(authenticated: false);
        var result = await ctl.Download("com/example/proxied/1.0/proxied-1.0.jar", CancellationToken.None);

        Assert.IsType<FileStreamResult>(result).FileStream.Dispose();
    }

    [Fact]
    public async Task Download_UnknownArtifact_Returns404()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        var result = await ctl.Download("com/example/missing/9.9/missing-9.9.jar", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_ArtifactOwnedByAnotherOrg_IsNotServed()
    {
        // maven_version_files has no org_id column of its own: a row is bound to a tenant only
        // through package_versions → packages.org_id, and the serve query's `p.org_id = @orgId`
        // predicate is the entire tenancy boundary. Seed the coordinate under the OTHER org only;
        // acme requests the exact same GAV + filename. Dropping that predicate would serve the
        // other tenant's bytes, so this pins it.
        await SetAnonymousPullAsync(true);
        byte[] otherBytes = Encoding.UTF8.GetBytes("other-tenant-jar");
        await SeedMavenProxyArtifactForOrgAsync(_otherOrgId, "com.example", "tenantsplit", "1.0", otherBytes);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/tenantsplit/1.0/tenantsplit-1.0.jar", CancellationToken.None);

        // No local row for acme and no upstream configured ⇒ 404. Never the other org's file.
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_SameCoordinateInTwoOrgs_ServesTheCallersOwnBytes()
    {
        // Both tenants hold the identical GAV + filename. The caller must get its OWN blob —
        // a missing org predicate would let whichever row the LIMIT 1 happened to pick win.
        await SetAnonymousPullAsync(true);
        await SeedMavenProxyArtifactForOrgAsync(
            _otherOrgId, "com.example", "shared", "2.0", Encoding.UTF8.GetBytes("other-tenant-bytes"));
        await SeedMavenProxyArtifactAsync("com.example", "shared", "2.0", Encoding.UTF8.GetBytes("acme-bytes"));

        var ctl = BuildController();
        var result = await ctl.Download("com/example/shared/2.0/shared-2.0.jar", CancellationToken.None);

        var file = Assert.IsType<FileStreamResult>(result);
        using var reader = new StreamReader(file.FileStream);
        Assert.Equal("acme-bytes", await reader.ReadToEndAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Download_StoredChecksumSidecar_ReturnsHex()
    {
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("primary-bytes");
        await SeedMavenProxyArtifactAsync("com.example", "lib", "1.2.3", bytes);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.2.3/lib-1.2.3.jar.sha1", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(200, content.StatusCode);
        Assert.Equal("text/plain", content.ContentType);
        Assert.Equal(
            Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant(),
            content.Content);
    }

    [Fact]
    public async Task Download_Sha512Sidecar_ComputedFromBlob()
    {
        // sha512 isn't in the per-file columns; the controller reads the blob and hashes on
        // demand. This exercises the BlobKeys.StoreKey + ComputeChecksumAsync branch.
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("primary-bytes-for-sha512");
        await SeedMavenProxyArtifactAsync("com.example", "lib", "2.0", bytes);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/2.0/lib-2.0.jar.sha512", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(200, content.StatusCode);
        Assert.Equal(
            Convert.ToHexString(SHA512.HashData(bytes)).ToLowerInvariant(),
            content.Content);
    }

    [Fact]
    public async Task Download_MetadataXml_Returns200_WithVersions()
    {
        await SetAnonymousPullAsync(true);
        byte[] b1 = Encoding.UTF8.GetBytes("v1");
        byte[] b2 = Encoding.UTF8.GetBytes("v2");
        await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", b1);
        await SeedMavenProxyArtifactAsync("com.example", "lib", "2.0", b2);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/maven-metadata.xml", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/xml", content.ContentType);
        Assert.Contains("1.0", content.Content);
        Assert.Contains("2.0", content.Content);
    }

    [Fact]
    public async Task Download_MetadataXml_NoVersions_Returns404()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        var result = await ctl.Download("com/example/ghost/maven-metadata.xml", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_MetadataChecksumSidecar_ReturnsHash()
    {
        // metadata sidecar (.md5/.sha1 on maven-metadata.xml) hashes the generated body.
        await SetAnonymousPullAsync(true);
        await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("x"));

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/maven-metadata.xml.md5", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/plain", content.ContentType);
        Assert.False(string.IsNullOrWhiteSpace(content.Content));
    }

    [Fact]
    public async Task Download_MetadataChecksumSidecar_MatchesServedMetadataBody()
    {
        // mvn fetches maven-metadata.xml, then its sidecar, as separate requests. Both are
        // generated on the fly, so the body must be byte-stable across requests or the
        // client's checksum validation fails.
        await SetAnonymousPullAsync(true);
        await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("x"));

        var ctl = BuildController();
        var body = Assert.IsType<ContentResult>(
            await ctl.Download("com/example/lib/maven-metadata.xml", CancellationToken.None));
        var sidecar = Assert.IsType<ContentResult>(
            await ctl.Download("com/example/lib/maven-metadata.xml.sha1", CancellationToken.None));

        // mirrors the Maven-spec .sha1 sidecar, not a security check.
        string expected = Convert.ToHexString(
            SHA1.HashData(Encoding.UTF8.GetBytes(body.Content!))).ToLowerInvariant();
        Assert.Equal(expected, sidecar.Content);
    }

    // ── Artifact-level metadata ordering over the shared cache plane ────────────

    // Every version set below is chosen so that the lexically-greatest version is NOT the
    // semantically-newest (1.9 sorts above 1.10 as text). That matters for what these tests
    // prove: MAX(created_at) cannot separate rows that share the backfill's one timestamp, so
    // the engine is free to return them in any order — and the order SQLite's plan happens to
    // produce for this GROUP BY is the version text. A set whose text-max coincides with its
    // version-max would therefore resolve <latest> correctly by accident and pin nothing.

    [Fact]
    public async Task Download_MetadataXml_CachePlaneVersionsTiedOnFirstCachedAt_LatestIsSemanticallyNewest()
    {
        // The upgraded-deployment shape: every proxied version of a coordinate carries the one
        // shared timestamp the cache-plane backfill wrote. <latest>/<release> must resolve from
        // the version set itself, and <versions> must come back in Maven's order — 1.10 is newer
        // than 1.9, which is exactly what the tie order left behind gets backwards.
        await SetAnonymousPullAsync(true);
        foreach (string version in new[] { "1.10", "1.9", "1.0" })
        {
            await SeedMavenCachePlaneVersionAsync("com.example", "lib", version);
        }
        await AssertCachePlaneTimestampsTiedAsync("com.example:lib", 3);

        var versioning = await ServedVersioningAsync(
            BuildController(), "com/example/lib/maven-metadata.xml");

        Assert.Equal("1.10", versioning.Element("latest")!.Value);
        Assert.Equal("1.10", versioning.Element("release")!.Value);
        Assert.Equal(
            new[] { "1.0", "1.9", "1.10" },
            versioning.Element("versions")!.Elements("version").Select(e => e.Value));
    }

    [Fact]
    public async Task Download_MetadataXml_TiedFirstCachedAt_ResolvesFromTheVersionSetNotRowArrivalOrder()
    {
        // The byte-stability the ETag and the .sha1/.md5 sidecars rest on: the document must be a
        // function of the version SET alone. Two coordinates get the same versions seeded in
        // opposite orders; with one shared first_cached_at across every row, arrival order is the
        // only thing separating them, and on a tie an engine is free to hand it straight back.
        //
        // The <versioning> equality is the weaker half of this test — SQLite's plan for this
        // GROUP BY sorts by version text, so arrival order is already invisible to it and that
        // assertion holds either way. The value it resolves to is the half that bites: a text
        // order makes 1.9 the last row and therefore the reported <latest>.
        await SetAnonymousPullAsync(true);
        string[] versions = ["1.0", "1.9", "1.10"];
        foreach (string version in versions)
        {
            await SeedMavenCachePlaneVersionAsync("com.example", "asc", version);
        }
        foreach (string version in versions.Reverse())
        {
            await SeedMavenCachePlaneVersionAsync("com.example", "desc", version);
        }
        await AssertCachePlaneTimestampsTiedAsync("com.example:asc", 3);
        await AssertCachePlaneTimestampsTiedAsync("com.example:desc", 3);

        // A fresh controller per request gets a fresh rendered-response cache, so each of these
        // is a genuine rebuild off the rows rather than a cache hit.
        var ascending = await ServedVersioningAsync(
            BuildController(), "com/example/asc/maven-metadata.xml");
        var descending = await ServedVersioningAsync(
            BuildController(), "com/example/desc/maven-metadata.xml");

        Assert.Equal(ascending.ToString(), descending.ToString());
        Assert.Equal("1.10", ascending.Element("latest")!.Value);
        Assert.Equal(versions, ascending.Element("versions")!.Elements("version").Select(e => e.Value));
    }

    [Fact]
    public async Task Download_MetadataXml_SnapshotAndReleaseOnCachePlane_LatestTakesSnapshot_ReleaseSkipsIt()
    {
        // The <latest>/<release> distinction, over rows that all share one first_cached_at:
        // <latest> takes the newest version outright (the in-flight 1.11-SNAPSHOT), <release>
        // the newest non-SNAPSHOT (1.10). Under the leftover text order both land on 1.9.
        await SetAnonymousPullAsync(true);
        foreach (string version in new[] { "1.2", "1.9", "1.10", "1.11-SNAPSHOT" })
        {
            await SeedMavenCachePlaneVersionAsync("com.example", "lib", version);
        }
        await AssertCachePlaneTimestampsTiedAsync("com.example:lib", 4);

        var versioning = await ServedVersioningAsync(
            BuildController(), "com/example/lib/maven-metadata.xml");

        Assert.Equal("1.11-SNAPSHOT", versioning.Element("latest")!.Value);
        Assert.Equal("1.10", versioning.Element("release")!.Value);
    }

    [Fact]
    public async Task Download_MetadataXml_MixedHostedAndTiedCachePlaneVersions_LatestSpansBothPlanes()
    {
        // Mixed shape, the one an upgraded deployment actually carries: part of the coordinate is
        // published locally (package_versions, a real per-publish created_at) and part was proxied
        // onto the cache plane by the backfill (every row on one shared timestamp). The two planes'
        // timestamps are unrelated, so <latest> must come from the newest version across the union
        // — never from whichever plane's rows happen to sort last, which is what hands back the
        // hosted 1.5 here.
        await SetAnonymousPullAsync(true);
        await SeedMavenArtifactAsync("com.example", "lib", "1.5", Encoding.UTF8.GetBytes("hosted"));
        foreach (string version in new[] { "1.10", "1.9", "1.0" })
        {
            await SeedMavenCachePlaneVersionAsync("com.example", "lib", version);
        }
        await AssertCachePlaneTimestampsTiedAsync("com.example:lib", 3);

        var versioning = await ServedVersioningAsync(
            BuildController(), "com/example/lib/maven-metadata.xml");

        Assert.Equal("1.10", versioning.Element("latest")!.Value);
        Assert.Equal("1.10", versioning.Element("release")!.Value);
        // Both planes contribute; the union is deduplicated by version, not by plane. Compared as
        // a set — the two planes' created_at values are unrelated, so which one leads the list is
        // not a property this test should pin.
        Assert.Equal(
            new[] { "1.0", "1.5", "1.9", "1.10" },
            versioning.Element("versions")!.Elements("version").Select(e => e.Value).Order(MavenVersionComparer.Instance));
    }

    // ── Version-level SNAPSHOT metadata (g/a/{version}/maven-metadata.xml) ──────

    [Fact]
    public async Task Download_SnapshotVersionMetadataXml_EmitsSnapshotAndSnapshotVersions()
    {
        // Pins the gap: a hosted SNAPSHOT publish with multiple timestamped builds must
        // resolve g/a/1.0-SNAPSHOT/maven-metadata.xml to a document carrying the <snapshot>
        // (newest build) and <snapshotVersions> (every timestamped file) blocks — not the
        // artifact-level version list the old code returned at this path regardless of the
        // requested version segment.
        await SetAnonymousPullAsync(true);
        await SeedMavenSnapshotFileAsync(
            "com.example", "lib", "1.0-SNAPSHOT", "lib-1.0-20240101.120000-1.jar", "jar", null);
        await SeedMavenSnapshotFileAsync(
            "com.example", "lib", "1.0-SNAPSHOT", "lib-1.0-20240102.130000-2.jar", "jar", null);
        await SeedMavenSnapshotFileAsync(
            "com.example", "lib", "1.0-SNAPSHOT", "lib-1.0-20240102.130000-2.pom", "pom", null);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0-SNAPSHOT/maven-metadata.xml", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.StartsWith("application/xml", content.ContentType);
        var doc = System.Xml.Linq.XDocument.Parse(content.Content!);
        Assert.Equal("1.0-SNAPSHOT", doc.Root!.Element("version")!.Value);

        var versioning = doc.Root.Element("versioning")!;
        var snapshot = versioning.Element("snapshot")!;
        Assert.Equal("20240102.130000", snapshot.Element("timestamp")!.Value);
        Assert.Equal("2", snapshot.Element("buildNumber")!.Value);

        // All three files carry a resolvable deploy timestamp, so all three are listed — the
        // older build-1 jar stays resolvable by its own timestamped filename even though it's
        // no longer the newest build the top-level <snapshot> element points at.
        var snapshotVersions = versioning.Element("snapshotVersions")!.Elements("snapshotVersion").ToList();
        Assert.Equal(3, snapshotVersions.Count);
        Assert.Contains(snapshotVersions, sv => sv.Element("value")!.Value == "1.0-20240101.120000-1");
        Assert.Contains(snapshotVersions, sv =>
            sv.Element("value")!.Value == "1.0-20240102.130000-2" && sv.Element("extension")!.Value == "jar");
        Assert.Contains(snapshotVersions, sv =>
            sv.Element("value")!.Value == "1.0-20240102.130000-2" && sv.Element("extension")!.Value == "pom");
    }

    [Fact]
    public async Task Download_SnapshotVersionMetadataXml_NoHostedFiles_Returns404()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        var result = await ctl.Download("com/example/ghost/1.0-SNAPSHOT/maven-metadata.xml", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_SnapshotVersionMetadataXml_IsIndependentOfArtifactLevelMetadata()
    {
        // The two "maven-metadata.xml" requests at different path depths must not collide in
        // the rendered-response cache: the artifact-level document (all versions) and the
        // version-level SNAPSHOT document (build list) are different content for the same
        // groupId/artifactId. Fetching one first must not poison the other.
        await SetAnonymousPullAsync(true);
        await SeedMavenSnapshotFileAsync(
            "com.example", "lib", "1.0-SNAPSHOT", "lib-1.0-20240101.120000-1.jar", "jar", null);

        var ctl = BuildController();
        var artifactLevel = Assert.IsType<ContentResult>(
            await ctl.Download("com/example/lib/maven-metadata.xml", CancellationToken.None));
        var versionLevel = Assert.IsType<ContentResult>(
            await ctl.Download("com/example/lib/1.0-SNAPSHOT/maven-metadata.xml", CancellationToken.None));

        var artifactDoc = System.Xml.Linq.XDocument.Parse(artifactLevel.Content!);
        var versionDoc = System.Xml.Linq.XDocument.Parse(versionLevel.Content!);

        // Artifact-level lists versions and has no <version>/<snapshot> element; version-level
        // carries <version> and <snapshot> and no <versions> list.
        Assert.NotNull(artifactDoc.Root!.Element("versioning")!.Element("versions"));
        Assert.Null(artifactDoc.Root.Element("version"));
        Assert.NotNull(versionDoc.Root!.Element("version"));
        Assert.NotNull(versionDoc.Root.Element("versioning")!.Element("snapshot"));
    }

    // ── Block gate (vuln/manual gate on download) ───────────────────────

    private async Task SetManualBlockStateAsync(string versionId, string state)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET manual_block_state = @state WHERE id = @id",
            new { state, id = versionId });
    }

    private async Task SetMaxOsvToleranceAsync(double tolerance)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @t WHERE org_id = @org",
            new { t = tolerance, org = _orgId });
    }

    // Marks the version scanned and links one advisory carrying the given CVSS score so the
    // block gate's OSV branch sees a real max-score (it only evaluates once vuln_checked_at is set).
    private async Task SeedScannedVulnAsync(string versionId, double cvssScore)
    {
        await using var conn = await _db.OpenAsync();
        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score)
            VALUES (@id, @osv, 'maven', 'com.example:lib', 'HIGH', @score)
            """,
            new { id = vulnId, osv = $"OSV-{Guid.NewGuid():N}", score = cvssScore });
        string pvvId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) VALUES (@pvvId, @pv, @vuln, 'package_version')",
            new { pvvId, pv = versionId, vuln = vulnId });
        await conn.ExecuteAsync(
            "UPDATE package_versions SET vuln_checked_at = @ts WHERE id = @id",
            new { ts = _clock.GetUtcNow().ToString("o"), id = versionId });
    }

    [Fact]
    public async Task Download_ManualBlockedVersion_Returns403()
    {
        await SetAnonymousPullAsync(true);
        var (_, verId, _) = await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("blocked-jar"));
        await SetManualBlockStateAsync(verId, "blocked");

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);
    }

    [Fact]
    public async Task Download_VulnScoreOverTolerance_Returns403()
    {
        await SetAnonymousPullAsync(true);
        await SetMaxOsvToleranceAsync(4.0);
        var (_, verId, _) = await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("vuln-jar"));
        await SeedScannedVulnAsync(verId, 9.8);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);
    }

    [Fact]
    public async Task Download_BlockedVersionChecksumSidecar_Returns403()
    {
        // The gate runs before the sidecar branch, so a blocked artifact's checksums don't leak.
        await SetAnonymousPullAsync(true);
        var (_, verId, _) = await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("blocked-sidecar-jar"));
        await SetManualBlockStateAsync(verId, "blocked");

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0/lib-1.0.jar.sha1", CancellationToken.None);

        Assert.Equal(403, Assert.IsType<StatusCodeResult>(result).StatusCode);
    }

    [Fact]
    public async Task Download_VulnScoreWithinTolerance_StillServes()
    {
        // Scanned and carries an advisory, but the score is within tolerance → served, not blocked.
        await SetAnonymousPullAsync(true);
        await SetMaxOsvToleranceAsync(10.0);
        var (_, verId, _) = await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("tolerable-jar"));
        await SeedScannedVulnAsync(verId, 5.0);

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);

        Assert.IsType<FileStreamResult>(result).FileStream.Dispose();
    }

    [Fact]
    public async Task Download_ManualAllowOverridesVulnScore_Serves()
    {
        // Operator override: manual_block_state='allowed' short-circuits the OSV gate.
        await SetAnonymousPullAsync(true);
        await SetMaxOsvToleranceAsync(4.0);
        var (_, verId, _) = await SeedMavenProxyArtifactAsync("com.example", "lib", "1.0", Encoding.UTF8.GetBytes("allowed-despite-vuln"));
        await SeedScannedVulnAsync(verId, 9.8);
        await SetManualBlockStateAsync(verId, "allowed");

        var ctl = BuildController();
        var result = await ctl.Download("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);

        Assert.IsType<FileStreamResult>(result).FileStream.Dispose();
    }

    // ── HEAD ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Head_ExistingArtifact_Returns200_WithContentType()
    {
        await SetAnonymousPullAsync(true);
        byte[] bytes = Encoding.UTF8.GetBytes("jar-content");
        await SeedMavenProxyArtifactAsync("com.example", "headtest", "1.0", bytes);

        var ctl = BuildController();
        var result = await ctl.Head("com/example/headtest/1.0/headtest-1.0.jar", CancellationToken.None);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(200, content.StatusCode);
        Assert.Equal("application/java-archive", content.ContentType);
    }

    [Fact]
    public async Task Head_MissingArtifact_Returns404()
    {
        await SetAnonymousPullAsync(true);
        var ctl = BuildController();
        var result = await ctl.Head("com/example/nope/1.0/nope-1.0.jar", CancellationToken.None);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── PUT / Publish ───────────────────────────────────────────────────────

    private static void SetBody(HttpContext ctx, byte[] bytes)
    {
        ctx.Request.Body = new MemoryStream(bytes);
        ctx.Request.ContentLength = bytes.LongLength;
    }

    [Fact]
    public async Task Publish_EmptyPath_Returns400()
    {
        var ctl = BuildController();
        var result = await ctl.Publish("", CancellationToken.None);
        Assert.IsType<BadRequestResult>(result);
    }

    [Fact]
    public async Task Publish_UnparseablePath_Returns400()
    {
        var ctl = BuildController();
        var result = await ctl.Publish("too/short", CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Publish_NoAuth_Returns401()
    {
        var ctl = BuildController();
        var result = await ctl.Publish("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(result);
        Assert.Contains("Basic", ctl.Response.Headers.WWWAuthenticate.ToString());
    }

    [Fact]
    public async Task Publish_CrossTenantToken_Returns401()
    {
        // Token issued for _otherOrgId but presented at a route bound to _orgId. The org-scoped
        // overload of ResolveTokenAsync returns null for cross-tenant — controller treats that
        // identically to "no token" and 401s.
        string otherUser = await UserSeeder.InsertAsync(_db, _otherOrgId, "intruder@other.test", "owner");
        string raw = await IssueTokenAsync(_otherOrgId, otherUser);

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("nope"));

        var result = await ctl.Publish("com/example/lib/1.0/lib-1.0.jar", CancellationToken.None);
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task Publish_HappyPath_ReturnsCreated_AndPersists()
    {
        string raw = await IssueTokenAsync(_orgId, _userId);
        byte[] bytes = Encoding.UTF8.GetBytes("real-jar-bytes");

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, bytes);

        var result = await ctl.Publish("com/example/newlib/1.0/newlib-1.0.jar", CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);
        Assert.True(ctl.Response.Headers.ContainsKey("X-Dependably-PURL"));

        // Verify the row landed.
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:newlib'
            """,
            new { org = _orgId });
        Assert.Equal(1, count);

        // And the blob was written under the content-addressed hosted key. The controller uses
        // coords.PackageName.Replace(':','/') = "com.example/newlib" — the dotted group is
        // kept intact (only the g:a separator becomes '/') — plus the artefact's SHA-256 as the
        // penultimate segment, so bytes under a key always hash to the digest the key names.
        // The blob layout differs from the request path layout (which uses g/a/v/file form) by design.
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.HostedArtifact(
            _orgId, "maven", "com.example/newlib", "1.0", sha256, "newlib-1.0.jar");
        Assert.True(await _blobs.ExistsAsync(blobKey, CancellationToken.None));
    }

    [Fact]
    public async Task Publish_Pom_ExtractsLicenses_ToPackageVersionRow()
    {
        string raw = await IssueTokenAsync(_orgId, _userId);
        byte[] pom = Encoding.UTF8.GetBytes("""
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>pomlic</artifactId>
              <version>1.0</version>
              <licenses>
                <license>
                  <name>The Apache Software License, Version 2.0</name>
                  <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
                </license>
                <license>
                  <name>MIT License</name>
                </license>
              </licenses>
            </project>
            """);

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, pom);

        var result = await ctl.Publish("com/example/pomlic/1.0/pomlic-1.0.pom", CancellationToken.None);
        Assert.Equal(201, Assert.IsType<StatusCodeResult>(result).StatusCode);

        await using var conn = await _db.OpenAsync();
        var spdx = (await conn.QueryAsync<string>(
            """
            SELECT pvl.license_spdx FROM package_version_licenses pvl
            JOIN package_versions pv ON pv.id = pvl.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:pomlic'
            ORDER BY pvl.license_spdx
            """,
            new { org = _orgId })).ToList();
        Assert.Equal(new[] { "Apache-2.0", "MIT" }, spdx);
    }

    [Fact]
    public async Task Publish_Jar_WritesNoLicenseRows()
    {
        string raw = await IssueTokenAsync(_orgId, _userId);

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("just-a-jar"));

        var result = await ctl.Publish("com/example/jarlic/1.0/jarlic-1.0.jar", CancellationToken.None);
        Assert.Equal(201, Assert.IsType<StatusCodeResult>(result).StatusCode);

        await using var conn = await _db.OpenAsync();
        long rows = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_version_licenses pvl
            JOIN package_versions pv ON pv.id = pvl.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:jarlic'
            """,
            new { org = _orgId });
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task Publish_ExceedsTenantSizeCap_Returns413_BeforeStoringBlob()
    {
        // The cap is resolved before the body is read, and the body is streamed through a
        // LimitedReadStream at that cap — so an oversize upload is rejected (413) while streaming,
        // before any blob is written.
        await SetMaxUploadMavenAsync(8);
        string raw = await IssueTokenAsync(_orgId, _userId);
        byte[] bytes = Encoding.UTF8.GetBytes("this-jar-body-is-well-over-eight-bytes");

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, bytes);

        var result = await ctl.Publish("com/example/toobig/1.0/toobig-1.0.jar", CancellationToken.None);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(413, status.StatusCode);

        Assert.DoesNotContain(await HostedKeysAsync(), k => k.EndsWith("/toobig-1.0.jar", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Publish_Republish_OverwritesFileRow()
    {
        // The ON CONFLICT clause on maven_version_files (package_version_id, filename) keeps
        // exactly one row per (version, file) — a second push overwrites checksums.
        string raw = await IssueTokenAsync(_orgId, _userId);

        byte[] first = Encoding.UTF8.GetBytes("first-bytes");
        var ctl1 = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl1.HttpContext, first);
        await ctl1.Publish("com/example/repub/1.0/repub-1.0.jar", CancellationToken.None);

        byte[] second = Encoding.UTF8.GetBytes("second-bytes-distinct");
        var ctl2 = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl2.HttpContext, second);
        var result = await ctl2.Publish("com/example/repub/1.0/repub-1.0.jar", CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);

        await using var conn = await _db.OpenAsync();
        string? sha = await conn.ExecuteScalarAsync<string>(
            """
            SELECT mvf.checksum_sha256 FROM maven_version_files mvf
            JOIN package_versions pv ON pv.id = mvf.package_version_id
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @org AND p.purl_name = 'com.example:repub'
              AND mvf.filename = 'repub-1.0.jar'
            """,
            new { org = _orgId });
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(second)).ToLowerInvariant(),
            sha);
    }

    [Fact]
    public async Task Publish_MetadataXml_ReturnsCreated_DiscardsBody()
    {
        // maven-metadata.xml uploads from the client are accepted-and-discarded — we always
        // re-derive metadata at GET time from package_versions.
        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("<metadata/>"));

        var result = await ctl.Publish("com/example/lib/maven-metadata.xml", CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);

        // No package_versions / maven_version_files row should be created for the metadata upload.
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE org_id = @org AND purl_name = 'com.example:lib'",
            new { org = _orgId });
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task Publish_ArtifactPathWithoutVersion_Returns400()
    {
        // Maven artifact PUT paths must include a version segment. A metadata-shaped path
        // (g/a/maven-metadata.xml) without one is accepted (metadata branch) but a plain
        // artifact at g/a/file.jar without a version-looking dir parses as metadata-no-version
        // and is rejected by the !IsMetadata check.
        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("body"));

        // 3 segments where the last looks like a metadata file → parses as artifact-level
        // metadata, Version=null, IsMetadata=true. Controller treats it as a metadata upload
        // and returns 201. So instead test a true unparseable layout:
        var result = await ctl.Publish("com/example/lib", CancellationToken.None);
        // Less than 3 segments → MavenPathParser returns null → 400.
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Publish_PathTraversalSegment_Returns400()
    {
        // PathSafeValidator runs per-segment after we accept the parse. ".." in a segment
        // is rejected even though Maven path parsing might otherwise tolerate the shape.
        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("evil"));

        // groupId segment contains "..": parser accepts it (segments split cleanly on '/'),
        // PathSafeValidator rejects it.
        var result = await ctl.Publish("com/..bad/lib/1.0/lib-1.0.jar", CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Publish_ExceedsPerTenantMavenCap_Returns413()
    {
        await SetMaxUploadMavenAsync(8);  // tiny cap so any real payload trips it
        string raw = await IssueTokenAsync(_orgId, _userId);

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("definitely-larger-than-eight"));

        var result = await ctl.Publish("com/example/big/1.0/big-1.0.jar", CancellationToken.None);

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(413, status.StatusCode);
    }

    [Fact]
    public async Task Publish_MatchingChecksumSidecar_Returns201()
    {
        // Seed primary first, then upload its sidecar — the controller looks up the stored
        // sha1 and confirms our upload matches.
        byte[] bytes = Encoding.UTF8.GetBytes("primary-for-sidecar");
        await SeedMavenArtifactAsync("com.example", "sidelib", "1.0", bytes);

        string raw = await IssueTokenAsync(_orgId, _userId);
        string sha1Hex = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();

        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes(sha1Hex + "  sidelib-1.0.jar\n"));

        var result = await ctl.Publish("com/example/sidelib/1.0/sidelib-1.0.jar.sha1", CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);
    }

    [Fact]
    public async Task Publish_MismatchedChecksumSidecar_Returns400()
    {
        byte[] bytes = Encoding.UTF8.GetBytes("primary-bytes-for-mismatch");
        await SeedMavenArtifactAsync("com.example", "mismatch", "1.0", bytes);

        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        // Wrong hex — controller's ExtractHex pulls "dead..." out and finds it doesn't match
        // the stored sha1.
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));

        var result = await ctl.Publish("com/example/mismatch/1.0/mismatch-1.0.jar.sha1", CancellationToken.None);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("mismatch", bad.Value!.ToString()!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Publish_SidecarBeforePrimary_AcceptedAsInformational()
    {
        // The "no primary yet" branch: a client uploads the sidecar first, before the primary.
        // The controller has no expected hash to compare against and returns 201.
        string raw = await IssueTokenAsync(_orgId, _userId);
        var ctl = BuildController(authHeader: $"Bearer {raw}");
        SetBody(ctl.HttpContext, Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef01234567"));

        var result = await ctl.Publish("com/example/early/1.0/early-1.0.jar.sha1", CancellationToken.None);

        var status = Assert.IsType<StatusCodeResult>(result);
        Assert.Equal(201, status.StatusCode);
    }
}
