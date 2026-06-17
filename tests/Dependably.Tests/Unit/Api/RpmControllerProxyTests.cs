using System.Security.Claims;
using System.Security.Cryptography;
using System.Xml.Linq;
using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
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

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Proxy-path coverage for <see cref="RpmController"/>.
///
/// Coverage targets:
///  - GET package: local miss → proxy resolves → UpstreamClient fetches → DB row written → bytes served
///  - GET package: local miss → resolution null → 404 + negative cache written
///  - GET package: local miss → negative cache hit → 404 without resolve
///  - GET package: proxy null (no upstream) → 404
///  - GET package: passthrough disabled → 404
///  - GET repodata/repomd.xml: passthrough → 200 with ETag
///  - GET repodata/repomd.xml: passthrough → 304 (If-None-Match matches)
///  - GET repodata/{hash}-primary.xml.gz: served from proxy
///  - GET repodata/RPM-GPG-KEY: returns key bytes with pgp-keys content type
///  - GET repodata/repomd.xml: no upstream → local generation
///  - PUT upload: passthrough mode → 409 with ProblemDetails
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmControllerProxyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    private string _orgId = null!;
    private string _userId = null!;

    private OrgRepository _orgs = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private PackageRepository _packages = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        _orgs = new OrgRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);
        _packages = new PackageRepository(_db);

        _orgId = await OrgSeeder.InsertAsync(_db, "rpm-proxy-org");
        _userId = await UserSeeder.InsertAsync(_db, _orgId, "dev@rpm.test", "admin");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ────────────────────────────────────────────────────────────────

    private async Task EnableAnonPullAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
            new { orgId = _orgId });
    }

    /// <summary>
    /// Seeds one rpm upstream registry for the test org so the controller's
    /// <see cref="UpstreamRegistryResolver"/> returns a non-empty list and the proxy path runs.
    /// Without this the org has zero configured rpm registries (proxying disabled = 404).
    /// </summary>
    private async Task SeedRpmRegistryAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
            VALUES (@id, @orgId, 'rpm', 'https://rpm.example.test/repo', 0)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId = _orgId });
    }

    // ── Package proxy ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Download_LocalMiss_FetchesFromUpstreamAndCachesInDb()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "tree-2.1.1-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/t/{filename}",
            Sha256: sha256,
            Name: "tree",
            Epoch: 0,
            Version: "2.1.1",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A recursive directory listing command",
            Description: "tree is a recursive...",
            License: "GPLv2+");

        // Pre-stage the blob in the cache tier so UpstreamClient.GetOrFetchAsync returns a hit.
        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download(filename, default);

        // Should serve bytes (the proxy path returns FileStreamResult via File(MemoryStream,...)).
        var fsr = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(bytes, ms.ToArray());
        Assert.Equal("application/x-rpm", fsr.ContentType);

        // DB row should be written.
        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleOrDefaultAsync(
            """
            SELECT pv.checksum_sha256, pv.origin
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm'
              AND p.purl_name = 'tree'
              AND pv.filename = @filename
            """,
            new { orgId = _orgId, filename });

        Assert.NotNull(row);
        var r = row!;
        Assert.Equal(sha256, (string)r.checksum_sha256);
        Assert.Equal("proxy", (string)r.origin);
    }

    [Fact]
    public async Task DownloadNested_UpstreamHrefPath_ResolvesViaFlatFilename()
    {
        // dnf composes baseurl + the upstream <location href> ("Packages/t/<file>"),
        // so the nested route must resolve to the same flat-filename download flow.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] bytes = RandomBytes(256);
        string sha256 = Sha256Hex(bytes);
        string filename = "tree-2.1.1-1.fc40.x86_64.rpm";
        var resolution = new PackageResolution(
            PackageUrl: $"https://mirror.example.com/Packages/t/{filename}",
            Sha256: sha256,
            Name: "tree",
            Epoch: 0,
            Version: "2.1.1",
            Release: "1.fc40",
            Arch: "x86_64",
            Summary: "A recursive directory listing command",
            Description: "tree is a recursive...",
            License: "GPLv2+");

        await _blobs.PutAsync(BlobKeys.Proxy(sha256), new MemoryStream(bytes), default);

        var stubProxy = new StubProxy(resolution: resolution);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.DownloadNested("t", filename, default);

        var fsr = Assert.IsType<FileStreamResult>(result);
        using var ms = new MemoryStream();
        await fsr.FileStream.CopyToAsync(ms);
        Assert.Equal(bytes, ms.ToArray());
        Assert.Equal("application/x-rpm", fsr.ContentType);

        // The proxy must have been asked to resolve the flat filename, not the nested path.
        Assert.Equal(filename, stubProxy.LastResolvedFilename);
    }

    [Fact]
    public async Task DownloadNested_NonRpm_ReturnsBadRequest()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: new StubProxy(resolution: null));

        var result = await ctl.DownloadNested("r", "repomd.xml", default);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Download_LocalMiss_ResolutionNull_Returns404AndRecordsNegative()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(resolution: null);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("nonexistent-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.True(stubProxy.NegativeRecorded);
    }

    [Fact]
    public async Task Download_LocalMiss_NegativelyCached_Returns404WithoutResolve()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(resolution: null, negativeCache: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("cached-neg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    [Fact]
    public async Task Download_NoProxy_Returns404()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Download_PassthroughDisabled_Returns404()
    {
        await EnableAnonPullAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET proxy_passthrough_enabled = 0 WHERE org_id = @orgId",
            new { orgId = _orgId });

        var stubProxy = new StubProxy(resolution: null, assertNotCalled: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    [Fact]
    public async Task Download_NoRpmRegistryConfigured_Returns404()
    {
        // Empty upstream list = proxying disabled for the ecosystem, even with the proxy
        // in passthrough mode. The controller must 404 without consulting the proxy.
        await EnableAnonPullAsync();
        // Deliberately no SeedRpmRegistryAsync(): the org has zero configured rpm registries.
        var stubProxy = new StubProxy(resolution: null, assertNotCalled: true);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Download("pkg-1.0-1.fc40.x86_64.rpm", default);

        Assert.IsType<NotFoundResult>(result);
        Assert.False(stubProxy.ResolveWasCalled);
    }

    // ── Repodata proxy ────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_Returns200WithETag()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        byte[] repomdBytes = System.Text.Encoding.UTF8.GetBytes("<repomd/>");
        var repodata = new RepodataResult(repomdBytes, "application/xml", "\"abc\"", null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata("repomd.xml", default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(repomdBytes, fc.FileContents);
        Assert.Equal("application/xml", fc.ContentType);
    }

    [Fact]
    public async Task Repodata_RepomdXml_Passthrough_304Propagated()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        var repodata = new RepodataResult([], "application/xml", "\"abc\"", null, NotModified: true);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.IfNoneMatch = "\"abc\"";

        var result = await ctl.Repodata("repomd.xml", default);

        Assert.Equal(304, ((StatusCodeResult)result).StatusCode);
    }

    [Fact]
    public async Task Repodata_HashPrefixedFile_PassthroughServes()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        string sha256 = new('a', 64);
        string filename = $"{sha256}-primary.xml.gz";
        byte[] body = new byte[] { 1, 2, 3 };
        var repodata = new RepodataResult(body, "application/x-gzip", null, null, NotModified: false);
        var stubProxy = new StubProxy(repodataResult: repodata);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.Repodata(filename, default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(body, fc.FileContents);
        Assert.Equal("application/x-gzip", fc.ContentType);
    }

    [Fact]
    public async Task Repodata_NoUpstream_ServesLocalRepomd()
    {
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        // With an empty org (no packages), local repomd.xml should still return 200.
        var result = await ctl.Repodata("repomd.xml", default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal("application/xml", fc.ContentType);
    }

    // ── GPG key ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GpgKey_ProxyReturnsKey_Returns200WithCorrectContentType()
    {
        await SeedRpmRegistryAsync();
        byte[] keyBytes = System.Text.Encoding.ASCII.GetBytes("-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
        var stubProxy = new StubProxy(gpgKey: keyBytes);
        var ctl = BuildController(proxy: stubProxy);

        var result = await ctl.GpgKey(default);

        var fc = Assert.IsType<FileContentResult>(result);
        Assert.Equal(keyBytes, fc.FileContents);
        Assert.Equal("application/pgp-keys", fc.ContentType);
    }

    [Fact]
    public async Task GpgKey_NoProxy_Returns404()
    {
        var ctl = BuildController(proxy: null);
        var result = await ctl.GpgKey(default);
        Assert.IsType<NotFoundResult>(result);
    }

    // ── Upload passthrough refusal ────────────────────────────────────────────

    [Fact]
    public async Task Upload_PassthroughMode_Returns409WithProblemDetails()
    {
        await SeedRpmRegistryAsync();
        var stubProxy = new StubProxy(isPassthrough: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream();

        var result = await ctl.Upload(default);

        var conflict = Assert.IsType<ConflictObjectResult>(result);
        var problem = Assert.IsType<ProblemDetails>(conflict.Value);
        Assert.Equal(409, problem.Status);
        Assert.Contains("passthrough", problem.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Rpm:UpstreamMode", problem.Detail);
    }

    // ── Merged mode ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Repodata_MergedMode_RepomdAndPrimary_UnionLocalAndUpstream_Consistent()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("hello", "2.10", "1.el9", "x86_64");

        // Upstream advertises a colliding hello (must be shadowed) + a unique tree (must survive).
        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("hello", "2.10", "1.el9", "x86_64", "Packages/h/hello-2.10-1.el9.x86_64.rpm"),
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: upstreamGz);

        // Same controller instance for both calls so they share the merged-primary cache —
        // dnf fetches repomd.xml first, then the primary.xml.gz it points at.
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var primaryResult = Assert.IsType<FileContentResult>(await ctl.Repodata("primary.xml.gz", default));

        // The SHA-256 repomd seals must match the exact primary.xml.gz bytes served.
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var repomd = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));
        string sealedSha = repomd.Descendants(repo + "checksum").First().Value;
        Assert.Equal(Sha256Hex(primaryResult.FileContents), sealedSha);

        // The served primary unions local hello (flat href, shadowing upstream) + upstream tree.
        XNamespace common = "http://linux.duke.edu/metadata/common";
        var primaryDoc = XDocument.Parse(Gunzip(primaryResult.FileContents));
        var names = primaryDoc.Root!.Elements(common + "package")
            .Select(p => p.Element(common + "name")!.Value).OrderBy(n => n).ToList();
        Assert.Equal(new[] { "hello", "tree" }, names);

        var hello = primaryDoc.Root.Elements(common + "package")
            .Single(p => p.Element(common + "name")!.Value == "hello");
        Assert.Equal("packages/hello-2.10-1.el9.x86_64.rpm",
            hello.Element(common + "location")!.Attribute("href")!.Value);
        var tree = primaryDoc.Root.Elements(common + "package")
            .Single(p => p.Element(common + "name")!.Value == "tree");
        Assert.Equal("packages/tree-2.1.1-1.el9.x86_64.rpm",
            tree.Element(common + "location")!.Attribute("href")!.Value);
    }

    [Fact]
    public async Task Repodata_MergedMode_UpstreamUnreachable_FallsBackToLocalRepomd()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        // upstreamPrimaryGz null ⇒ GetUpstreamPrimaryXmlGzAsync returns null ⇒ fall back to local.
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: null);
        var ctl = BuildController(proxy: stubProxy);

        var result = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        Assert.Equal("application/xml", result.ContentType);
    }

    [Fact]
    public async Task Repodata_MergedMode_RepomdContainsPrimaryAndFilelistsEntries()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("hello", "2.10", "1.el9", "x86_64");

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true, upstreamPrimaryGz: upstreamGz);
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var filelistsResult = Assert.IsType<FileContentResult>(await ctl.Repodata("filelists.xml.gz", default));

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.Contains("primary", types);
        Assert.Contains("filelists", types);

        // The filelists sha256 in repomd must match the actual bytes served.
        var filelistsEntry = repomdDoc.Root.Elements(repo + "data")
            .Single(e => (string?)e.Attribute("type") == "filelists");
        string sealedSha = filelistsEntry.Element(repo + "checksum")!.Value;
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(filelistsResult.FileContents)).ToLowerInvariant(),
            sealedSha);
    }

    [Fact]
    public async Task Repodata_MergedMode_UpstreamNonPrimaryEntriesPreserved()
    {
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var updateinfoEntry = new XElement(repo + "data",
            new XAttribute("type", "updateinfo"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{new string('a', 64)}-updateinfo.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { updateinfoEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.Contains("updateinfo", types);
    }

    [Fact]
    public async Task Repodata_MergedMode_AdvertisedHrefs_AllServable_UpstreamEntryProxied()
    {
        // Merged repomd advertises an upstream updateinfo entry. dnf fetches repomd.xml and then
        // follows every advertised href — none may 404, and the hash-prefixed updateinfo href
        // must be proxied through the upstream fetch path with the upstream's exact bytes.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        string sha256 = new('c', 64);
        string updateinfoFilename = $"{sha256}-updateinfo.xml.gz";
        byte[] updateinfoBytes = System.Text.Encoding.UTF8.GetBytes("<updates/>");

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var updateinfoEntry = new XElement(repo + "data",
            new XAttribute("type", "updateinfo"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{updateinfoFilename}")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));

        // The stub returns the updateinfo bytes for hash-prefixed GetRepodataAsync calls only,
        // mirroring the real proxy's filename gate.
        var repodataResult = new RepodataResult(updateinfoBytes, "application/x-gzip", null, null, NotModified: false);
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { updateinfoEntry },
            repodataResult: repodataResult);
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var hrefs = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => e.Element(repo + "location")!.Attribute("href")!.Value)
            .ToList();
        Assert.Contains($"repodata/{updateinfoFilename}", hrefs);

        // Every advertised href must be fetchable — the contract dnf relies on.
        foreach (string href in hrefs)
        {
            string filename = href[(href.LastIndexOf('/') + 1)..];
            var fetched = await ctl.Repodata(filename, default);
            Assert.IsNotType<NotFoundResult>(fetched);
        }

        // The advertised updateinfo href serves the upstream stub's exact bytes.
        var result = Assert.IsType<FileContentResult>(await ctl.Repodata(updateinfoFilename, default));
        Assert.Equal("application/x-gzip", result.ContentType);
        Assert.Equal(updateinfoBytes, result.FileContents);
    }

    [Fact]
    public async Task Repodata_MergedMode_PlainNamedUpstreamEntry_DroppedFromMergedRepomd()
    {
        // An upstream entry with a plain (non-content-addressed) href — e.g. classic-createrepo
        // comps.xml.gz — cannot be proxied by the repodata dispatch. It must be dropped from the
        // merged repomd rather than advertised as an href that would 404; dnf treats absent
        // supplemental metadata as non-fatal.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();

        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var compsEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", "repodata/comps.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm"));
        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { compsEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.DoesNotContain("group", types);
    }

    [Fact]
    public async Task Repodata_LocalMode_ServesFilelistsAndOtherXmlGz()
    {
        await EnableAnonPullAsync();

        var ctl = BuildController(proxy: null);

        var filelistsResult = Assert.IsType<FileContentResult>(await ctl.Repodata("filelists.xml.gz", default));
        Assert.Equal("application/x-gzip", filelistsResult.ContentType);

        var otherResult = Assert.IsType<FileContentResult>(await ctl.Repodata("other.xml.gz", default));
        Assert.Equal("application/x-gzip", otherResult.ContentType);
    }

    [Fact]
    public async Task Repodata_LocalMode_RepomdContainsPrimaryFilelistsOther()
    {
        await EnableAnonPullAsync();

        var ctl = BuildController(proxy: null);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var doc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = doc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).OrderBy(t => t).ToList();
        Assert.Equal(new[] { "filelists", "other", "primary" }, types);
    }

    [Fact]
    public async Task Upload_MergedMode_NotBlockedByPassthroughGuard()
    {
        // Merged mode must NOT trip the passthrough publish guard. With a valid token the request
        // flows past the guard into the normal upload pipeline (here a too-small body → 400),
        // proving it is no longer the 409 conflict passthrough returns.
        await SeedRpmRegistryAsync();
        string raw = await SeedPublishTokenAsync();
        var stubProxy = new StubProxy(isPassthrough: false, isMerged: true);
        var ctl = BuildController(proxy: stubProxy);
        ctl.ControllerContext.HttpContext.Request.Headers.Authorization = $"Bearer {raw}";
        ctl.ControllerContext.HttpContext.Request.Body = new MemoryStream(new byte[10]);

        var result = await ctl.Upload(default);

        Assert.IsNotType<ConflictObjectResult>(result);
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Contains("too small", bad.Value?.ToString() ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // ── Group/module metadata limitation ─────────────────────────────────────

    [Fact]
    public async Task Repodata_LocalMode_CompsXmlGz_Returns404_NoBrokenDocumentServed()
    {
        // Dependably does not generate comps (group) metadata for locally published RPMs.
        // A request for comps.xml.gz in local-only mode must return 404, not an empty or
        // malformed XML document. dnf treats absent supplemental metadata as non-fatal.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Repodata("comps.xml.gz", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Repodata_LocalMode_ModulesYaml_Returns404_NoBrokenDocumentServed()
    {
        // Same limitation for modulemd — modular (AppStream) metadata is not generated by
        // Dependably for locally published RPMs.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var result = await ctl.Repodata("modules.yaml.gz", default);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Repodata_LocalMode_RepomdDoesNotAdvertiseGroupOrModules()
    {
        // The locally generated repomd.xml must not advertise group, modules, or any supplemental
        // metadata entry — only primary, filelists, and other are generated locally.
        // Advertising an entry that returns 404 would break dnf's metadata integrity check.
        await EnableAnonPullAsync();
        var ctl = BuildController(proxy: null);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        XNamespace repo = "http://linux.duke.edu/metadata/repo";
        var doc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));

        var types = doc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.DoesNotContain("group", types);
        Assert.DoesNotContain("modules", types);
        Assert.DoesNotContain("comps", types);
    }

    [Fact]
    public async Task Repodata_MergedMode_MixedPartialResult_LocalPackageAndUpstreamGroupBothHandled()
    {
        // Mixed partial-failure scenario (house rule): merged mode where the repo contains a
        // locally published package (appears in primary/filelists as expected), the upstream
        // has a hash-prefixed group entry (forwarded verbatim), AND the upstream has a
        // plain-named comps entry (dropped). All three outcomes must hold in the same response.
        await EnableAnonPullAsync();
        await SeedRpmRegistryAsync();
        await SeedLocalRpmAsync("myapp", "1.0", "1.el9", "x86_64");

        string groupSha = new('e', 64);
        string groupFilename = $"{groupSha}-comps.xml.gz";

        XNamespace repo = "http://linux.duke.edu/metadata/repo";

        // Upstream provides two supplemental entries:
        //   1. hash-prefixed group — servable, must appear in merged repomd
        //   2. plain-named comps — not servable, must be dropped from merged repomd
        var hashPrefixedGroupEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", $"repodata/{groupFilename}")));
        var plainCompsEntry = new XElement(repo + "data",
            new XAttribute("type", "group"),
            new XElement(repo + "location",
                new XAttribute("href", "repodata/comps.xml.gz")));

        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("upstream-lib", "2.0", "1.el9", "x86_64", "Packages/u/upstream-lib-2.0-1.el9.x86_64.rpm"));

        var stubProxy = new StubProxy(
            isPassthrough: false,
            isMerged: true,
            upstreamPrimaryGz: upstreamGz,
            upstreamNonPrimaryEntries: new[] { hashPrefixedGroupEntry, plainCompsEntry });
        var ctl = BuildController(proxy: stubProxy);

        var repomdResult = Assert.IsType<FileContentResult>(await ctl.Repodata("repomd.xml", default));
        var primaryResult = Assert.IsType<FileContentResult>(await ctl.Repodata("primary.xml.gz", default));

        var repomdDoc = XDocument.Parse(System.Text.Encoding.UTF8.GetString(repomdResult.FileContents));
        var advertisedTypes = repomdDoc.Root!.Elements(repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();

        // Local package appears in primary union.
        XNamespace common = "http://linux.duke.edu/metadata/common";
        var primaryDoc = XDocument.Parse(Gunzip(primaryResult.FileContents));
        var names = primaryDoc.Root!.Elements(common + "package")
            .Select(p => p.Element(common + "name")!.Value).OrderBy(n => n).ToList();
        Assert.Contains("myapp", names);
        Assert.Contains("upstream-lib", names);

        // Hash-prefixed group entry is forwarded — it appears in the merged repomd.
        Assert.Contains("group", advertisedTypes);
        var groupEntry = repomdDoc.Root.Elements(repo + "data")
            .Single(e => (string?)e.Attribute("type") == "group");
        Assert.Contains(groupFilename, groupEntry.Element(repo + "location")!.Attribute("href")!.Value);

        // Plain-named comps entry is dropped — only one group entry (the hash-prefixed one).
        Assert.Single(repomdDoc.Root.Elements(repo + "data"),
            e => (string?)e.Attribute("type") == "group");

        // comps.xml.gz (plain-named, not content-addressed) returns 404 — not a broken document.
        var compsResult = await ctl.Repodata("comps.xml.gz", default);
        Assert.IsType<NotFoundResult>(compsResult);
    }

    private async Task<string> SeedPublishTokenAsync()
    {
        var (raw, _) = await _tokens.CreateUserTokenAsync(
            _orgId, _userId, """["publish:rpm"]""", expiresAt: null);
        return raw;
    }

    private async Task SeedLocalRpmAsync(string name, string ver, string rel, string arch)
    {
        string pkgId = await PackageSeeder.InsertAsync(_db, _orgId, "rpm", name, purlName: name);
        string pvId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId,
            version: $"{ver}-{rel}",
            purl: $"pkg:rpm/{name}@{ver}-{rel}?arch={arch}",
            blobKey: $"rpm/registry/{name}-{ver}-{rel}.{arch}.rpm",
            checksumSha256: new string('a', 64));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, installed_size, archive_size, header_start, header_end, rpm_license)
            VALUES (@pvId, @name, 0, @ver, @rel, @arch, 'sum', 'desc', 1, 1, 0, 1, 'MIT')
            """,
            new { pvId, name, ver, rel, arch });
    }

    private static byte[] BuildUpstreamPrimaryGz(
        params (string Name, string Ver, string Rel, string Arch, string Href)[] pkgs)
    {
        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpm = "http://linux.duke.edu/metadata/rpm";
        var doc = new XDocument(
            new XElement(common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", rpm.NamespaceName),
                new XAttribute("packages", pkgs.Length),
                pkgs.Select(p => new XElement(common + "package",
                    new XAttribute("type", "rpm"),
                    new XElement(common + "name", p.Name),
                    new XElement(common + "arch", p.Arch),
                    new XElement(common + "version",
                        new XAttribute("epoch", 0), new XAttribute("ver", p.Ver), new XAttribute("rel", p.Rel)),
                    new XElement(common + "checksum",
                        new XAttribute("type", "sha256"), new XAttribute("pkgid", "YES"), new string('b', 64)),
                    new XElement(common + "size",
                        new XAttribute("package", 1), new XAttribute("installed", 1), new XAttribute("archive", 1)),
                    new XElement(common + "location", new XAttribute("href", p.Href)),
                    new XElement(common + "format", new XElement(rpm + "license", "MIT"))))));
        return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(doc.ToString()));
    }

    private static string Gunzip(byte[] gz)
    {
        using var input = new System.IO.Compression.GZipStream(
            new MemoryStream(gz), System.IO.Compression.CompressionMode.Decompress);
        using var ms = new MemoryStream();
        input.CopyTo(ms);
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    // ── Controller builder ────────────────────────────────────────────────────

    private RpmController BuildController(IRpmUpstreamProxy? proxy = null)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("rpm-proxy-org.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(_orgId, "rpm-proxy-org");
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, _userId),
                new Claim("sub", _userId),
                new Claim("org_id", _orgId),
                new Claim("tid", _orgId),
                new Claim("role", "admin"),
                new Claim("scope", "tenant"),
            ],
            authenticationType: "test"));

        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        // Build a real UpstreamClient that reads from _blobs (cache tier).
        // Tests that need the proxy path pre-stage the blob so GetOrFetchAsync returns a HIT.
        var upstreamClient = BuildRealUpstreamClient();

        var svc = new RpmControllerServices(
            Packages: _packages,
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: new TieredBlobStorage(_blobs, _blobs),
            Db: _db,
            Repodata: new RpmRepodataService(_db, NullLogger<RpmRepodataService>.Instance, TimeProvider.System),
            Registries: new UpstreamRegistryResolver(new UpstreamRegistryRepository(_db, TimeProvider.System)),
            MergedRepodataCache: new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmMergedRepodata),
            LocalRepodataCache: new RenderedResponseCache<RpmLocalRepodataKey>(
                new MemoryCache(new MemoryCacheOptions()), MetadataCacheKeys.RpmLocalRepodata),
            Time: TimeProvider.System,
            UpstreamClient: upstreamClient,
            Proxy: proxy);

        return new RpmController(svc)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private UpstreamClient BuildRealUpstreamClient()
    {
        // UpstreamClient with no-op HttpClient (should not be called — blobs are pre-staged).
        var httpFactory = new NullHttpClientFactory();
        return new UpstreamClient(
            httpFactory,
            new TieredBlobStorage(_blobs, _blobs),
            _audit,
            new AllowAllValidator(),
            new DisabledAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(Path.GetTempPath()),
            Dependably.Infrastructure.StagingOptions.Resolve(new ConfigurationBuilder().Build()),
            NullLogger<UpstreamClient>.Instance);
    }

    private static byte[] RandomBytes(int n = 64)
    {
        byte[] b = new byte[n];
        Random.Shared.NextBytes(b);
        return b;
    }

    private static string Sha256Hex(byte[] d)
        => Convert.ToHexString(SHA256.HashData(d)).ToLowerInvariant();

    // ── Test doubles ──────────────────────────────────────────────────────────

    /// <summary>
    /// Stub implementation of <see cref="IRpmUpstreamProxy"/> for controller unit tests.
    /// All methods return the pre-configured values; call tracking lets tests assert
    /// that methods were (or were not) called.
    /// </summary>
    private sealed class StubProxy : IRpmUpstreamProxy
    {
        private readonly PackageResolution? _resolution;
        private readonly bool _negativeCache;
        private readonly RepodataResult? _repodataResult;
        private readonly byte[]? _gpgKey;
        private readonly byte[]? _upstreamPrimaryGz;
        private readonly bool _assertNotCalled;
        private readonly IReadOnlyList<XElement> _upstreamNonPrimaryEntries;

        public bool NegativeRecorded { get; private set; }
        public bool ResolveWasCalled { get; private set; }
        public string? LastResolvedFilename { get; private set; }
        public string? LastUpstreamBase { get; private set; }

        public StubProxy(
            PackageResolution? resolution = null,
            bool negativeCache = false,
            RepodataResult? repodataResult = null,
            byte[]? gpgKey = null,
            bool isPassthrough = true,
            bool isMerged = false,
            byte[]? upstreamPrimaryGz = null,
            bool assertNotCalled = false,
            IReadOnlyList<XElement>? upstreamNonPrimaryEntries = null)
        {
            _resolution = resolution;
            _negativeCache = negativeCache;
            _repodataResult = repodataResult;
            _gpgKey = gpgKey;
            IsPassthroughModeSelected = isPassthrough;
            IsMergedModeSelected = isMerged;
            _upstreamPrimaryGz = upstreamPrimaryGz;
            _assertNotCalled = assertNotCalled;
            _upstreamNonPrimaryEntries = upstreamNonPrimaryEntries ?? Array.Empty<XElement>();
        }

        public bool IsPassthroughModeSelected { get; }
        public bool IsMergedModeSelected { get; }

        public Task<byte[]?> GetUpstreamPrimaryXmlGzAsync(string upstreamBase, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_upstreamPrimaryGz);
        }

        public Task<byte[]?> GetUpstreamFilelistsXmlGzAsync(string upstreamBase, CancellationToken ct)
            => Task.FromResult<byte[]?>(null);

        public Task<IReadOnlyList<XElement>> GetUpstreamNonPrimaryRepomdEntriesAsync(string upstreamBase, CancellationToken ct)
            => Task.FromResult(_upstreamNonPrimaryEntries);

        public Task<PackageResolution?> ResolvePackageUrlAsync(string upstreamBase, string filename, CancellationToken ct)
        {
            if (_assertNotCalled)
            {
                throw new InvalidOperationException($"ResolvePackageUrlAsync must not be called (filename={filename})");
            }

            ResolveWasCalled = true;
            LastResolvedFilename = filename;
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_resolution);
        }

        public Task<bool> IsNegativelyCachedAsync(string path, CancellationToken ct)
            => Task.FromResult(_negativeCache);

        public Task RecordNegativeAsync(string path, CancellationToken ct)
        {
            NegativeRecorded = true;
            return Task.CompletedTask;
        }

        public Task<RepodataResult?> GetRepodataAsync(string upstreamBase, string filename, string? ifNoneMatch, string? ifModifiedSince, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;

            // Mirror the real proxy's filename gate: only repomd passthrough names and
            // hash-prefixed (content-addressed) filenames are fetchable upstream.
            bool servable = filename.Equals("repomd.xml", StringComparison.OrdinalIgnoreCase)
                || filename.Equals("repomd.xml.asc", StringComparison.OrdinalIgnoreCase)
                || RpmUpstreamProxy.IsHashPrefixedFilename(filename);
            return Task.FromResult(servable ? _repodataResult : null);
        }

        public Task<byte[]?> GetGpgKeyAsync(string upstreamBase, CancellationToken ct)
        {
            LastUpstreamBase = upstreamBase;
            return Task.FromResult(_gpgKey);
        }
    }

    private sealed class NullHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new NullHandler());

        private sealed class NullHandler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
                => throw new InvalidOperationException("HTTP calls should not be made in proxy controller tests — pre-stage blobs instead.");
        }
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
    }
}
