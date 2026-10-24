using Dapper;
using Dependably.Api;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// An uploaded PyPI version shadows the proxied rows of the same PEP 440 version in listings, but
/// shadowing hides a row and never releases its gate: the simple index still withholds a blocked
/// proxied file. A block decision on one spelling covers every spelling on both planes; an
/// approval covers only the plane and spellings the operator decided.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiShadowedProxyGateTests
{
    private const string Name = "spell";
    private const string Uploaded = "1.0.0-rc1";
    private const string Proxied = "1.0.0rc1";
    private const string ProxiedFile = "spell-1.0.0rc1.tar.gz";

    private sealed record Seeded(ControllerScenarioResult B, CacheArtifact Cached, string PackageId, string VersionId);

    private static async Task<Seeded> SeedAsync(ControllerScenario s, params string[] uploadedSiblings)
    {
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync(Name, ecosystem: "pypi", isProxy: true);
        await s.WithPackageVersionAsync(Name, Uploaded, ecosystem: "pypi");
        foreach (string sibling in uploadedSiblings)
        {
            await s.WithPackageVersionAsync(Name, sibling, ecosystem: "pypi");
        }

        var b = await s.BuildAsync();

        var at = new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);
        var cached = await b.CacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = Name,
            Version = Proxied,
            Filename = ProxiedFile,
            BlobKey = $"proxy/{Guid.NewGuid():N}",
            ContentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            SizeBytes = 3,
            FirstCachedAt = at,
            LastAccessedAt = at,
        });
        await b.TenantAccess.UpsertAsync(b.PrimaryOrgId, cached.Id, at, TenantContentBinding.None);

        await using var conn = await b.Db.OpenAsync();
        var (PackageId, VersionId) = await conn.QuerySingleAsync<(string PackageId, string VersionId)>(
            """
            SELECT p.id AS PackageId, pv.id AS VersionId FROM packages p
            JOIN package_versions pv ON pv.package_id = p.id
            WHERE p.org_id = @orgId AND p.name = @name AND pv.version = @version
            """,
            new { orgId = b.PrimaryOrgId, name = Name, version = Uploaded });
        return new Seeded(b, cached, PackageId, VersionId);
    }

    private static async Task<string?> ProxyBlockStateAsync(Seeded x)
    {
        await using var conn = await x.B.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT manual_block_state FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @id",
            new { orgId = x.B.PrimaryOrgId, id = x.Cached.Id });
    }

    private static async Task<string?> UploadedBlockStateAsync(Seeded x)
    {
        await using var conn = await x.B.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT manual_block_state FROM package_versions WHERE id = @id", new { id = x.VersionId });
    }

    private static async Task<List<PyPiSimpleIndexHelper.SimpleIndexFileEntry>> IndexEntriesAsync(Seeded x)
    {
        var inventory = new ArtifactInventoryRepository(
            x.B.Db, new PackageRepository(x.B.Db), x.B.CacheArtifacts,
            new VulnerabilityRepository(x.B.Db, TimeProvider.System));
        var local = await inventory.ListServeableVersionsAsync(
            x.B.PrimaryOrgId, x.PackageId, "pypi", Name, includeShadowed: true);
        var signals = new Dictionary<string, VulnGateSignals>();
        var upstream = new[] { new PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry(ProxiedFile, "abc") };
        return PyPiSimpleIndexHelper.CollectSimpleIndexEntries(
            local, PyPiSimpleIndexHelper.NoHostedFiles, new OrgSettings { AnonymousPull = true },
            signals, new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero), upstream);
    }

    [Fact]
    public async Task CleanShadowedProxiedFile_IsStillAdvertised()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);

        var entries = await IndexEntriesAsync(x);

        Assert.Single(entries, e => e.Filename == ProxiedFile);
    }

    [Fact]
    public async Task ManuallyBlockedShadowedProxiedFile_IsWithheldFromTheIndex()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        await x.B.TenantAccess.SetManualBlockStateAsync(x.B.PrimaryOrgId, x.Cached.Id, "blocked");

        var entries = await IndexEntriesAsync(x);

        Assert.DoesNotContain(entries, e => e.Filename == ProxiedFile);
    }

    [Theory]
    [InlineData(Uploaded)]
    [InlineData(Proxied)]
    [InlineData("1.0.0RC1")]
    public async Task BlockVersion_AnySpelling_GatesBothPlanes(string spelling)
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);

        Assert.IsType<OkObjectResult>(
            await x.B.VulnerabilityController.BlockVersion("pypi", Name, spelling, CancellationToken.None));

        Assert.Equal("blocked", await UploadedBlockStateAsync(x));
        Assert.Equal("blocked", await ProxyBlockStateAsync(x));
        Assert.DoesNotContain(await IndexEntriesAsync(x), e => e.Filename == ProxiedFile);
    }

    // The proxied file carries a malicious advisory. A manual "allowed" short-circuits that arm,
    // so the file stays unservable only while nothing an operator did to the uploaded version
    // writes "allowed" onto the proxied row.
    private static async Task FlagProxiedMaliciousAsync(Seeded x)
    {
        await using var conn = await x.B.Db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE cache_artifact SET vuln_checked_at = @at WHERE id = @id",
            new { at = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero), id = x.Cached.Id });
    }

    private static async Task<bool> ProxiedFileServableAsync(Seeded x, bool malicious = true)
    {
        var entry = Assert.Single(
            await x.B.CacheArtifacts.ListServeFactsForNameAsync(x.B.PrimaryOrgId, "pypi", Name),
            e => e.Id == x.Cached.Id);
        var signals = malicious ? new VulnGateSignals(VulnFacts.None with { IsMalicious = true }) : null;
        return !BlockGateService.IsHardBlockedByCacheEntry(
            entry, new OrgSettings(), signals, new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnblockVersion_OnTheUploadedSpelling_NeverAllowsTheMaliciousProxiedFile(bool blockedFirst)
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        await FlagProxiedMaliciousAsync(x);
        string proxiedPurl = $"pkg:pypi/{Name}@{Proxied}";
        await new QuarantineRepository(x.B.Db, s.Clock).UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", proxiedPurl, "malicious", detail: null, packageVersionId: null);
        Assert.False(await ProxiedFileServableAsync(x));
        if (blockedFirst)
        {
            await x.B.VulnerabilityController.BlockVersion("pypi", Name, Uploaded, CancellationToken.None);
        }

        Assert.IsType<OkObjectResult>(
            await x.B.VulnerabilityController.UnblockVersion("pypi", Name, Uploaded, CancellationToken.None));

        Assert.Equal("allowed", await UploadedBlockStateAsync(x));
        Assert.Null(await ProxyBlockStateAsync(x));
        Assert.Equal(blockedFirst ? "denied" : "pending", await QuarantineStateAsync(x, proxiedPurl));
        Assert.False(await ProxiedFileServableAsync(x));
    }

    [Fact]
    public async Task QuarantineApprove_OnTheUploadedVersion_NeverAllowsTheMaliciousProxiedFile()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        await FlagProxiedMaliciousAsync(x);
        var quarantine = new QuarantineRepository(x.B.Db, s.Clock);
        string proxiedPurl = $"pkg:pypi/{Name}@{Proxied}";
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", proxiedPurl, "malicious", detail: null, packageVersionId: null);
        var uploaded = await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "release_age", detail: null,
            packageVersionId: x.VersionId);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(uploaded.RowId, new QuarantineDecisionRequest("approved")));

        Assert.Equal("allowed", await UploadedBlockStateAsync(x));
        Assert.Null(await ProxyBlockStateAsync(x));
        Assert.Equal("pending", await QuarantineStateAsync(x, proxiedPurl));
        Assert.False(await ProxiedFileServableAsync(x));
    }

    // A block that spread onto a shadowed proxied file has no other way back: the row is hidden
    // from the version list and a manual block queues no review entry. Unblocking the uploaded
    // version lifts it to no override, so a clean file serves again.
    [Fact]
    public async Task UnblockVersion_AfterASpreadBlock_LiftsTheBlockOnACleanProxiedFile()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        await x.B.VulnerabilityController.BlockVersion("pypi", Name, Uploaded, CancellationToken.None);
        Assert.False(await ProxiedFileServableAsync(x, malicious: false));

        Assert.IsType<OkObjectResult>(
            await x.B.VulnerabilityController.UnblockVersion("pypi", Name, Uploaded, CancellationToken.None));

        Assert.Null(await ProxyBlockStateAsync(x));
        Assert.True(await ProxiedFileServableAsync(x, malicious: false));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QuarantineApprove_AfterASpreadDeny_LiftsTheProxiedBlockWithoutAllowing(bool malicious)
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        if (malicious)
        {
            await FlagProxiedMaliciousAsync(x);
        }

        var uploaded = await new QuarantineRepository(x.B.Db, s.Clock).UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "release_age", detail: null,
            packageVersionId: x.VersionId);
        await x.B.QuarantineController.Decide(uploaded.RowId, new QuarantineDecisionRequest("denied"));
        Assert.Equal("blocked", await ProxyBlockStateAsync(x));

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(uploaded.RowId, new QuarantineDecisionRequest("approved")));

        Assert.Equal("allowed", await UploadedBlockStateAsync(x));
        Assert.Null(await ProxyBlockStateAsync(x));
        Assert.Equal(!malicious, await ProxiedFileServableAsync(x, malicious));
    }

    // Approving the proxied file's own entry is a decision about that file, so it does allow it,
    // and only it: the uploaded version keeps whatever state it had.
    [Fact]
    public async Task QuarantineApprove_OnTheProxiedEntry_AllowsOnlyThatFile()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        var upserted = await new QuarantineRepository(x.B.Db, s.Clock).UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Proxied}", "malicious", detail: null, packageVersionId: null);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(upserted.RowId, new QuarantineDecisionRequest("approved")));

        Assert.Equal("allowed", await ProxyBlockStateAsync(x));
        Assert.Null(await UploadedBlockStateAsync(x));
    }

    [Fact]
    public async Task QuarantineDeny_OnTheProxiedEntry_BlocksTheUploadedVersionAndResolvesItsEntry()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        var quarantine = new QuarantineRepository(x.B.Db, s.Clock);
        string uploadedPurl = $"pkg:pypi/{Name}@{Uploaded}";
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", uploadedPurl, "release_age", detail: null, packageVersionId: x.VersionId);
        var proxied = await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Proxied}", "malicious", detail: null, packageVersionId: null);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(proxied.RowId, new QuarantineDecisionRequest("denied")));

        Assert.Equal("blocked", await ProxyBlockStateAsync(x));
        Assert.Equal("blocked", await UploadedBlockStateAsync(x));
        Assert.Equal("denied", await QuarantineStateAsync(x, uploadedPurl));
    }

    [Fact]
    public async Task QuarantineDeny_OnTheUploadedVersion_CoversAnUploadedSiblingSpellingAndResolvesItsEntry()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s, "1.0.0.rc1");
        string siblingId = await SiblingVersionIdAsync(x, "1.0.0.rc1");
        var quarantine = new QuarantineRepository(x.B.Db, s.Clock);
        string siblingPurl = $"pkg:pypi/{Name}@1.0.0.rc1";
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", siblingPurl, "release_age", detail: null, packageVersionId: siblingId);
        string proxiedPurl = $"pkg:pypi/{Name}@{Proxied}";
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", proxiedPurl, "malicious", detail: null, packageVersionId: null);
        var decided = await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "malicious", detail: null,
            packageVersionId: x.VersionId);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(decided.RowId, new QuarantineDecisionRequest("denied")));

        Assert.Equal("blocked", await UploadedBlockStateAsync(x));
        Assert.Equal("blocked", await VersionBlockStateAsync(x, siblingId));
        Assert.Equal("blocked", await ProxyBlockStateAsync(x));
        Assert.Equal("denied", await QuarantineStateAsync(x, siblingPurl));
        Assert.Equal("denied", await QuarantineStateAsync(x, proxiedPurl));
    }

    // An approval stays on the uploaded plane, where every spelling is the operator's own upload.
    [Fact]
    public async Task QuarantineApprove_OnTheUploadedVersion_CoversAnUploadedSiblingSpelling()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s, "1.0.0.rc1");
        string siblingId = await SiblingVersionIdAsync(x, "1.0.0.rc1");
        var decided = await new QuarantineRepository(x.B.Db, s.Clock).UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "malicious", detail: null,
            packageVersionId: x.VersionId);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(decided.RowId, new QuarantineDecisionRequest("approved")));

        Assert.Equal("allowed", await VersionBlockStateAsync(x, siblingId));
        Assert.Null(await ProxyBlockStateAsync(x));
    }

    private static async Task<string> SiblingVersionIdAsync(Seeded x, string version)
    {
        await using var conn = await x.B.Db.OpenAsync();
        return await conn.QuerySingleAsync<string>(
            "SELECT id FROM package_versions WHERE package_id = @packageId AND version = @version",
            new { packageId = x.PackageId, version });
    }

    private static async Task<string?> VersionBlockStateAsync(Seeded x, string versionId)
    {
        await using var conn = await x.B.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT manual_block_state FROM package_versions WHERE id = @id", new { id = versionId });
    }

    [Fact]
    public async Task UnblockVersion_ProxyOnly_AllowsOnlyTheExactSpelling()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.UnblockVersion("pypi", "pair", "1.0rc1", CancellationToken.None));

        Assert.Equal("allowed", await PairBlockStateAsync(b, "1.0rc1"));
        Assert.Null(await PairBlockStateAsync(b, "1.0RC1"));
    }

    [Fact]
    public async Task BlockVersion_ProxyOnly_CoversEverySpelling()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        Assert.IsType<OkObjectResult>(
            await b.VulnerabilityController.BlockVersion("pypi", "pair", "1.0rc1", CancellationToken.None));

        Assert.Equal("blocked", await PairBlockStateAsync(b, "1.0rc1"));
        Assert.Equal("blocked", await PairBlockStateAsync(b, "1.0RC1"));
    }

    private static async Task<string?> PairBlockStateAsync(ControllerScenarioResult b, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT taa.manual_block_state FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.name = 'pair' AND ca.version = @version
            """,
            new { orgId = b.PrimaryOrgId, version });
    }

    [Fact]
    public async Task QuarantineDeny_OnTheUploadedVersion_BlocksTheShadowedProxiedRow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        var quarantine = new QuarantineRepository(x.B.Db, s.Clock);
        var upserted = await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "malicious", detail: null,
            packageVersionId: x.VersionId);

        Assert.IsType<OkObjectResult>(
            await x.B.QuarantineController.Decide(upserted.RowId, new QuarantineDecisionRequest("denied")));

        Assert.Equal("blocked", await UploadedBlockStateAsync(x));
        Assert.Equal("blocked", await ProxyBlockStateAsync(x));
    }

    private static async Task<string?> QuarantineStateAsync(Seeded x, string purl)
    {
        await using var conn = await x.B.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT state FROM quarantine WHERE org_id = @orgId AND purl = @purl",
            new { orgId = x.B.PrimaryOrgId, purl });
    }

    [Fact]
    public async Task BlockOnTheUploadedSpelling_ResolvesThePendingQuarantineOfTheProxiedSpelling()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        string proxiedPurl = $"pkg:pypi/{Name}@{Proxied}";
        await new QuarantineRepository(x.B.Db, s.Clock).UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", proxiedPurl, "malicious", detail: null, packageVersionId: null);

        Assert.IsType<OkObjectResult>(
            await x.B.VulnerabilityController.BlockVersion("pypi", Name, Uploaded, CancellationToken.None));

        Assert.Equal("denied", await QuarantineStateAsync(x, proxiedPurl));
    }

    // The review queue is the surface that could later approve the proxied row and undo the
    // block, so after a block on either spelling nothing for the release may remain pending.
    [Fact]
    public async Task BlockOnTheUploadedSpelling_LeavesNoPendingQuarantineEntryForTheRelease()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);
        var quarantine = new QuarantineRepository(x.B.Db, s.Clock);
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Proxied}", "malicious", detail: null, packageVersionId: null);
        await quarantine.UpsertPendingAsync(
            x.B.PrimaryOrgId, "pypi", $"pkg:pypi/{Name}@{Uploaded}", "malicious", detail: null,
            packageVersionId: x.VersionId);

        await x.B.VulnerabilityController.BlockVersion("pypi", Name, Proxied, CancellationToken.None);

        await using var conn = await x.B.Db.OpenAsync();
        long pending = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId AND state = 'pending'",
            new { orgId = x.B.PrimaryOrgId });
        Assert.Equal(0, pending);
        Assert.Equal("blocked", await ProxyBlockStateAsync(x));
    }

    private static async Task SeedProxyAsync(
        ControllerScenarioResult b, string version, string filename, DateTimeOffset cachedAt)
    {
        var artifact = await b.CacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = "pair",
            Version = version,
            Filename = filename,
            BlobKey = $"proxy/{Guid.NewGuid():N}",
            ContentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
            SizeBytes = 3,
            FirstCachedAt = cachedAt,
            LastAccessedAt = cachedAt,
        });
        await b.TenantAccess.UpsertAsync(b.PrimaryOrgId, artifact.Id, cachedAt, TenantContentBinding.None);
        await b.CacheBlobs.PutAsync(BlobKeys.StoreKey(artifact.BlobKey), new MemoryStream([1, 2, 3]), default);
    }

    // Two spellings of one release cached as separate rows (an old sdist beside a wheel), the
    // newer one the sdist. ListServeFactsForNameAsync orders newest first, so a canonical-first
    // lookup of the wheel's spelling would reach the sdist's row.
    private static async Task<ControllerScenarioResult> BuildPairAsync(ControllerScenario s)
    {
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        await s.WithPackageAsync("pair", ecosystem: "pypi", isProxy: true);
        var b = await s.BuildAsync();
        await SeedProxyAsync(b, "1.0rc1", "pair-1.0rc1-py3-none-any.whl", new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero));
        await SeedProxyAsync(b, "1.0RC1", "pair-1.0RC1.tar.gz", new DateTimeOffset(2026, 6, 1, 11, 0, 0, TimeSpan.Zero));
        return b;
    }

    private static async Task<long> PairRowsAsync(ControllerScenarioResult b, string version)
    {
        await using var conn = await b.Db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.name = 'pair' AND ca.version = @version
            """,
            new { orgId = b.PrimaryOrgId, version });
    }

    [Fact]
    public async Task DownloadVersion_ServesTheExactSpellingsRow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        var file = Assert.IsType<FileStreamResult>(
            await b.OrgController.DownloadVersion("pypi", "pair", "1.0rc1", CancellationToken.None));

        Assert.Equal("pair-1.0rc1-py3-none-any.whl", file.FileDownloadName);
        await file.FileStream.DisposeAsync();
    }

    [Fact]
    public async Task DownloadVersion_ASpellingWithNoExactRow_ResolvesCanonically()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        var file = Assert.IsType<FileStreamResult>(
            await b.OrgController.DownloadVersion("pypi", "pair", "1.0.rc1", CancellationToken.None));

        Assert.StartsWith("pair-1.0", file.FileDownloadName, StringComparison.Ordinal);
        await file.FileStream.DisposeAsync();
    }

    [Fact]
    public async Task DeleteVersion_RemovesOnlyTheExactSpellingsRow()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("pypi", "pair", "1.0rc1", CancellationToken.None));

        Assert.Equal(0, await PairRowsAsync(b, "1.0rc1"));
        Assert.Equal(1, await PairRowsAsync(b, "1.0RC1"));
    }

    [Fact]
    public async Task DeleteVersion_ASpellingWithNoExactRow_ResolvesCanonically()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var b = await BuildPairAsync(s);

        Assert.IsType<NoContentResult>(
            await b.OrgController.DeleteVersion("pypi", "pair", "1.0.rc1", CancellationToken.None));

        Assert.Equal(1, await PairRowsAsync(b, "1.0rc1") + await PairRowsAsync(b, "1.0RC1"));
    }

    [Fact]
    public async Task BlockVersion_ActivityDetailNamesEveryFlippedPurl()
    {
        await using var s = await ControllerScenario.CreateAsync();
        var x = await SeedAsync(s);

        await x.B.VulnerabilityController.BlockVersion("pypi", Name, Uploaded, CancellationToken.None);

        await using var conn = await x.B.Db.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'manual_block'",
            new { orgId = x.B.PrimaryOrgId });
        Assert.NotNull(detail);
        Assert.Contains($"pkg:pypi/{Name}@{Proxied}", detail);
        Assert.Contains("1.0.0-rc1", detail);
    }

    private static PackageVersion Row(string version, string filename) =>
        new() { Id = Guid.NewGuid().ToString("N"), Version = version, Filename = filename, Purl = "pkg:pypi/pair@" + version };

    [Fact]
    public void JsonApiInfoVersion_PrefersTheExactSpellingsRow()
    {
        // Newest first, as ListServeFactsForNameAsync returns proxied rows.
        var versions = new[] { Row("1.0RC1", "pair-1.0RC1.tar.gz"), Row("1.0rc1", "pair-1.0rc1-py3-none-any.whl") };

        var picked = PyPiJsonApiHandler.SelectInfoVersion(versions, "1.0rc1");

        Assert.Equal("pair-1.0rc1-py3-none-any.whl", picked?.Filename);
    }

    [Fact]
    public void JsonApiInfoVersion_ASpellingWithNoExactRow_ResolvesCanonically()
    {
        var versions = new[] { Row("1.0RC1", "pair-1.0RC1.tar.gz") };

        Assert.Equal("1.0RC1", PyPiJsonApiHandler.SelectInfoVersion(versions, "1.0.rc1")?.Version);
        Assert.Null(PyPiJsonApiHandler.SelectInfoVersion(versions, "1.0rc2"));
    }
}
