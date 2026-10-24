using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Rematch through HTTP: a scanner that opts in with <c>?kinds=scan,rematch</c> gets the sweep's
/// rematch jobs, reads the image's stored inventory, and posts new findings, and the server never
/// reads a byte of the image for it. Every rematch route is fenced like the rest of the scan API:
/// a job outside the org or of the wrong kind is 404, a superseded attempt 409.
/// </summary>
public sealed partial class OciScanApiTests
{
    private const string NewRecord = """
        {
          "id": "DSA-6666-1",
          "aliases": ["CVE-2026-6666"],
          "summary": "openssl issue, published after the scan",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
          "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
        }
        """;

    [Fact]
    public async Task ARematch_ReadsTheStoredInventory_AndPostsNewFindings_WithoutReadingAnyBlob()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/rematch", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        // The first scan reads the image, which the counter sees: it is not blind.
        var scan = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal("scan", scan.Kind);
        Assert.Equal(["rematch", "contentGaps"], scan.Capabilities);
        int readsBefore = _blobs.Reads;
        await ReadAsync(scanner, $"{scan.Id}/blobs/{image.LayerDigest}");
        Assert.True(_blobs.Reads > readsBefore);
        await PostOkAsync(scanner, $"{scan.Id}/result?attempt={scan.Attempt}", ScanBody(["DSA-5555-1"]));
        Assert.Equal("vulnerable", await StatusAsync("team/rematch", image.ManifestDigest));

        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal("rematch", rematch.Kind);

        int reads = _blobs.Reads;
        using (var manifest = await scanner.GetAsync($"/api/v1/oci-scan/{rematch.Id}/manifests/{image.ManifestDigest}"))
        using (var layer = await scanner.GetAsync($"/api/v1/oci-scan/{rematch.Id}/blobs/{image.LayerDigest}"))
        {
            Assert.Equal(HttpStatusCode.NotFound, manifest.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, layer.StatusCode);
        }

        using var inventory = await InventoryAsync(scanner, rematch);
        var platform = Assert.Single(inventory.RootElement.GetProperty("platforms").EnumerateArray().ToList());
        Assert.Equal("linux/amd64", platform.GetProperty("platform").GetString());
        Assert.Equal("1", platform.GetProperty("extractionVersion").GetString());
        Assert.Empty(platform.GetProperty("contentGaps").EnumerateArray());
        var component = Assert.Single(platform.GetProperty("components").EnumerateArray().ToList());
        Assert.Equal("openssl", component.GetProperty("sourceName").GetString());

        // OSV moved: the old advisory was withdrawn and a new one published.
        await PostOkAsync(scanner, $"{rematch.Id}/matches?attempt={rematch.Attempt}",
            MatchBody(platform.GetProperty("coverageId").GetString()!, component.GetProperty("id").GetString()!, ["DSA-6666-1"]));

        Assert.Equal(reads, _blobs.Reads);
        Assert.Equal(["DSA-6666-1"], await ImageLinksAsync(image.ManifestDigest));
        Assert.Equal("vulnerable", await StatusAsync("team/rematch", image.ManifestDigest));
        string now = _factory.FrozenClock.GetUtcNow().ToUtcIsoMillis();
        Assert.Equal(now, await VersionMatchedAtAsync("team/rematch", image.ManifestDigest));
        Assert.Equal(now, await LookupMatchedAtAsync("team/rematch", image.ManifestDigest));
        Assert.Equal(1, await CountAsync(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'oci_scan_rematch_result'", new { }));
    }

    [Fact]
    public async Task AScannerThatDoesNotAskForRematch_IsNeverHandedOne_AndOptsItsOrgOut()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/legacy", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        await ScanCleanAsync(scanner, kinds: "scan,rematch");
        Assert.Equal(1, await ScalarAsync<int>("SELECT MAX(accepts_rematch) FROM oci_scanners", new { }));
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));

        // A downgraded scanner claims without kinds, which opts the org out: the sweep queues nothing.
        Assert.Empty(await ClaimIdsAsync(scanner, kinds: null));
        Assert.Equal(0, await ScalarAsync<int>("SELECT MAX(accepts_rematch) FROM oci_scanners", new { }));
        Assert.Equal(0, await SweepAsync());

        // Opting back in brings the image's rematch.
        Assert.Empty(await ClaimIdsAsync(scanner, kinds: "scan,rematch"));
        Assert.Equal(1, await SweepAsync());

        // A claim without kinds is never handed the queued rematch.
        Assert.Empty(await ClaimIdsAsync(scanner, kinds: null));
        Assert.Equal("pending", await ScalarAsync<string>(
            "SELECT state FROM oci_scan_jobs WHERE kind = 'rematch' AND digest = @digest", new { digest = image.ManifestDigest }));
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT attempts FROM oci_scan_jobs WHERE kind = 'rematch' AND digest = @digest", new { digest = image.ManifestDigest }));
    }

    private static async Task<List<string>> ClaimIdsAsync(HttpClient scanner, string? kinds)
    {
        string query = kinds is null ? "" : $"?kinds={kinds}";
        using var claim = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/claim{query}", new { max = 16 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("jobs").EnumerateArray().Select(j => j.GetProperty("id").GetString()!).ToList();
    }

    [Fact]
    public async Task TheRematchRoutes_AreFencedByOrgKindAndAttempt()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        await PushImageAsync(push, "team/fenced-rematch", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));

        // A scan job is not a rematch job: every rematch route is 404 for it.
        var scan = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await AssertRematchRoutesAsync(scanner, scan.Id, scan.Attempt, HttpStatusCode.NotFound);
        await PostOkAsync(scanner, $"{scan.Id}/result?attempt={scan.Attempt}", ScanBody([]));

        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var stale = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        _factory.FrozenClock.Advance(TimeSpan.FromMinutes(16));
        var live = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal(stale.Id, live.Id);

        // A superseded attempt is 409 on every route; no attempt at all is refused outright.
        await AssertRematchRoutesAsync(scanner, live.Id, stale.Attempt, HttpStatusCode.Conflict);
        using (var bare = await scanner.GetAsync($"/api/v1/oci-scan/{live.Id}/inventory"))
        {
            Assert.Equal(HttpStatusCode.UnprocessableEntity, bare.StatusCode);
        }

        // Nor does an attempt no claim can have returned skip the fence.
        await AssertRematchRoutesAsync(scanner, live.Id, -1, HttpStatusCode.UnprocessableEntity);
        await AssertRematchRoutesAsync(scanner, live.Id, 0, HttpStatusCode.UnprocessableEntity);

        // Another org's rematch job is 404 even with its live attempt.
        string foreignJob = await SeedForeignRematchJobAsync();
        await AssertRematchRoutesAsync(scanner, foreignJob, 1, HttpStatusCode.NotFound);

        // The live holder is untouched by all of the above.
        using var inventory = await InventoryAsync(scanner, live);
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = live.Id }));
    }

    [Fact]
    public async Task Reextract_EndsTheRematch_AndQueuesAFreshScan_KeepingTheResultMeanwhile()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/escalate", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{first.Id}/result?attempt={first.Attempt}", ScanBody(["DSA-5555-1"]));
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        await SweepAsync();
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");

        using (var escalate = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{rematch.Id}/reextract?attempt={rematch.Attempt}",
            new { reason = "stored extraction 1 is older than oci-check 2" }))
        {
            Assert.Equal(HttpStatusCode.OK, escalate.StatusCode);
        }

        Assert.Equal("vulnerable", await StatusAsync("team/escalate", image.ManifestDigest));
        var rescan = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal("scan", rescan.Kind);
        Assert.NotEqual(first.Id, rescan.Id);
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM audit_log WHERE action = 'oci_scan_reextract'", new { }));

        // The first scan's holder, long gone, cannot write to the replacement.
        using var late = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{first.Id}/result?attempt={first.Attempt}", ScanBody([]));
        Assert.Equal(HttpStatusCode.Conflict, late.StatusCode);
    }

    [Fact]
    public async Task MatchesForAnInventoryReplacedSinceTheRead_Are409_AndWriteNothing()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/replaced", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{first.Id}/result?attempt={first.Attempt}", ScanBody(["DSA-5555-1"]));
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        using var inventory = await InventoryAsync(scanner, rematch);
        var platform = inventory.RootElement.GetProperty("platforms")[0];

        // A re-extraction of the same image lands before the scanner posts its matches.
        string orgId = await ScalarAsync<string>("SELECT org_id FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id });
        string versionId = await ScalarAsync<string>(
            "SELECT package_version_id FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id });
        var repo = _factory.Services.GetRequiredService<OciScanRepository>();
        using (DbScope.ForOrg(orgId))
        {
            await repo.RequeueAsync(orgId, OciScanOwner.Hosted(versionId), "team/replaced", image.ManifestDigest,
                OciScanKinds.Scan, _factory.FrozenClock.GetUtcNow().ToUtcIsoMillis());
        }

        var rescan = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        Assert.Equal("scan", rescan.Kind);
        await PostOkAsync(scanner, $"{rescan.Id}/result?attempt={rescan.Attempt}", ScanBody([]));

        using var stale = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{rematch.Id}/matches?attempt={rematch.Attempt}",
            MatchBody(platform.GetProperty("coverageId").GetString()!,
                platform.GetProperty("components")[0].GetProperty("id").GetString()!, ["DSA-6666-1"]));

        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Empty(await ImageLinksAsync(image.ManifestDigest));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_component_vulns", new { }));
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id }));
    }

    [Fact]
    public async Task AFailedRematch_KeepsThePreviousResult_AndIsRequeuedOneWindowAfterItIsParked()
    {
        using var push = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));
        var image = await PushImageAsync(push, "team/outage", "1.0");
        using var scanner = _factory.CreateClientWithBearer(await _factory.CreateToken("scanner"));
        var first = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{first.Id}/result?attempt={first.Attempt}", ScanBody(["DSA-5555-1"]));
        string matchedAt = await ScalarAsync<string>("SELECT matched_at FROM oci_scan_coverage", new { });
        _factory.FrozenClock!.Advance(TimeSpan.FromHours(25));
        await SweepAsync();

        // OSV is unreachable: the scanner fails the rematch as retryable, then for good.
        var rematch = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{rematch.Id}/fail?attempt={rematch.Attempt}",
            new { reason = "VULN_SOURCE_UNREACHABLE", retryable = true });
        Assert.Equal("vulnerable", await StatusAsync("team/outage", image.ManifestDigest));
        _factory.FrozenClock.Advance(TimeSpan.FromMinutes(2));
        var retry = await ClaimJobAsync(scanner, kinds: "scan,rematch");
        await PostOkAsync(scanner, $"{retry.Id}/fail?attempt={retry.Attempt}",
            new { reason = "VULN_SOURCE_UNREACHABLE", retryable = false });

        // Nothing about the image moved: its findings, links and last match are the scan's.
        Assert.Equal(matchedAt, await ScalarAsync<string>("SELECT matched_at FROM oci_scan_coverage", new { }));
        Assert.Equal(["DSA-5555-1"], await ImageLinksAsync(image.ManifestDigest));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_component_vulns", new { }));
        Assert.Equal("vulnerable", await StatusAsync("team/outage", image.ManifestDigest));
        Assert.Equal(0, await SweepAsync());
        _factory.FrozenClock.Advance(TimeSpan.FromHours(25));
        Assert.Equal(1, await SweepAsync());
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private sealed record ClaimedJob(string Id, string Kind, int Attempt, IReadOnlyList<string> Capabilities);

    private async Task<ClaimedJob> ClaimJobAsync(HttpClient scanner, string kinds)
    {
        using var claim = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/claim?kinds={kinds}", new { max = 1 });
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        using var body = JsonDocument.Parse(await claim.Content.ReadAsStringAsync());
        var job = Assert.Single(body.RootElement.GetProperty("jobs").EnumerateArray().ToList());
        return new ClaimedJob(
            job.GetProperty("id").GetString()!, job.GetProperty("kind").GetString()!, job.GetProperty("attempt").GetInt32(),
            body.RootElement.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!).ToList());
    }

    private async Task ScanCleanAsync(HttpClient scanner, string kinds)
    {
        var job = await ClaimJobAsync(scanner, kinds);
        await PostOkAsync(scanner, $"{job.Id}/result?attempt={job.Attempt}", ScanBody([]));
    }

    private static async Task PostOkAsync(HttpClient scanner, string path, object body)
    {
        using var response = await scanner.PostAsJsonAsync($"/api/v1/oci-scan/{path}", body);
        Assert.True(response.IsSuccessStatusCode, $"{path}: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private static async Task<JsonDocument> InventoryAsync(HttpClient scanner, ClaimedJob job)
    {
        using var response = await scanner.GetAsync($"/api/v1/oci-scan/{job.Id}/inventory?attempt={job.Attempt}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static async Task AssertRematchRoutesAsync(HttpClient scanner, string jobId, int attempt, HttpStatusCode expected)
    {
        using (var inventory = await scanner.GetAsync($"/api/v1/oci-scan/{jobId}/inventory?attempt={attempt}"))
        {
            Assert.Equal(expected, inventory.StatusCode);
        }

        using (var matches = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/matches?attempt={attempt}", MatchBody("coverage", "component", [])))
        {
            Assert.Equal(expected, matches.StatusCode);
        }

        using var reextract = await scanner.PostAsJsonAsync(
            $"/api/v1/oci-scan/{jobId}/reextract?attempt={attempt}", new { reason = "newer extractor" });
        Assert.Equal(expected, reextract.StatusCode);
    }

    private async Task<int> SweepAsync() =>
        await _factory.Services.GetRequiredService<OciScanSweepService>().RunPassAsync(default);

    // A rematch job leased to another org, on that org's own hosted image.
    private async Task<string> SeedForeignRematchJobAsync()
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        string orgId;
        // xtenant: test seeding of a second tenant; the request under test runs as the first.
        using (DbScope.CrossTenant("test seeds a second tenant's rematch job"))
        {
            orgId = await OrgSeeder.InsertAsync(db, "foreign-scanner-" + Guid.NewGuid().ToString("N")[..8]);
        }

        using (DbScope.ForOrg(orgId))
        {
            string pkg = await PackageSeeder.InsertAsync(db, orgId, "oci", "team/foreign");
            string version = await PackageSeeder.InsertVersionAsync(db, pkg, "sha256:" + new string('f', 64), "pkg:oci/foreign");
            var repo = _factory.Services.GetRequiredService<OciScanRepository>();
            var now = _factory.FrozenClock!.GetUtcNow();
            await repo.RequeueAsync(orgId, OciScanOwner.Hosted(version), "team/foreign", "sha256:" + new string('f', 64),
                OciScanKinds.Rematch, now.ToUtcIsoMillis());
            var job = Assert.Single(await repo.ClaimAsync(
                orgId, 1, 5, now.ToUtcIsoMillis(), now.AddMinutes(15).ToUtcIsoMillis(), includeRematch: true));
            return job.Id;
        }
    }

    private static object ScanBody(IReadOnlyList<string> vulns) => new
    {
        platforms = new[]
        {
            new
            {
                platform = "linux/amd64",
                scannerVersion = "0.4.0",
                extractionVersion = "1",
                osvSource = "remote",
                gaps = Array.Empty<string>(),
                contentGaps = Array.Empty<string>(),
                entrypointKind = "native",
                closureBounded = true,
                components = new[]
                {
                    new
                    {
                        purl = "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12&upstream=openssl",
                        ecosystem = "deb",
                        name = "libssl3",
                        version = "3.0.11-1~deb12u1",
                        sourceName = "openssl",
                        sourceVersion = "3.0.11-1~deb12u1",
                        layerIndex = 0,
                        vulns = vulns.Select(id => new { id, reachability = "reachable" }).ToArray(),
                        verdict = new { status = "reachable", confidence = "high" },
                    },
                },
            },
        },
        advisories = vulns.Select(id => JsonDocument.Parse(id == "DSA-6666-1" ? NewRecord : DsaRecord).RootElement).ToArray(),
    };

    private static object MatchBody(string coverageId, string componentId, IReadOnlyList<string> vulns) => new
    {
        platforms = new[]
        {
            new
            {
                platform = "linux/amd64",
                coverageId,
                osvSource = "remote",
                scannerVersion = "0.5.0",
                matchGaps = Array.Empty<string>(),
                findings = vulns.Count == 0
                    ? []
                    : new[] { new { componentId, vulns } },
            },
        },
        advisories = vulns.Select(id => JsonDocument.Parse(id == "DSA-6666-1" ? NewRecord : DsaRecord).RootElement).ToArray(),
    };

    private async Task<List<string>> ImageLinksAsync(string digest)
    {
        var db = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await db.OpenAsync();
        return (await conn.QueryAsync<string>(
            """
            SELECT v.osv_id FROM package_version_vulns pvv
            JOIN package_versions pv ON pv.id = pvv.package_version_id
            JOIN vulnerabilities v ON v.id = pvv.vuln_id
            WHERE pv.version = @digest ORDER BY v.osv_id
            """, new { digest })).ToList();
    }

    private async Task<string?> VersionMatchedAtAsync(string repository, string digest)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync($"/api/v1/packages/oci/{Uri.EscapeDataString(repository)}");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("versions").EnumerateArray()
            .Single(v => v.GetProperty("version").GetString() == digest)
            .GetProperty("matchedAt").GetString();
    }

    private async Task<string?> LookupMatchedAtAsync(string repository, string digest)
    {
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await _factory.CreateAdminJwt());
        using var response = await admin.GetAsync(
            $"/api/v1/lookup?ecosystem=oci&name={Uri.EscapeDataString(repository)}&version={Uri.EscapeDataString(digest)}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("advisorySource").GetProperty("matchedAt").GetString();
    }

    /// <summary>An <see cref="IBlobStore"/> that counts the reads it serves.</summary>
    private sealed class CountingBlobStore(IBlobStore inner) : IBlobStore
    {
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => inner.PutAsync(key, data, ct);

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _reads);
            return inner.GetAsync(key, ct);
        }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) => inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => inner.GetTotalSizeAsync(ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _reads);
            return inner.GetRangeAsync(key, from, to, ct);
        }

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => inner.ListAsync(prefix, ct);
    }
}
