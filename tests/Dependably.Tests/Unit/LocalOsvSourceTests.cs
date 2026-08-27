using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class LocalOsvSourceTests : IDisposable
{
    private readonly string _dir;

    public LocalOsvSourceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "osvtest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private void WriteAdvisory(
        string id, string ecosystem, string name, string[] versions,
        string? severity = null, string[]? aliases = null)
    {
        string sevBlock = severity is null ? "" : $@",
  ""severity"": [{{ ""type"": ""CVSS_V3"", ""score"": ""{severity}"" }}]";
        string aliasBlock = aliases is null ? "" : $@",
  ""aliases"": [{string.Join(",", aliases.Select(a => $"\"{a}\""))}]";
        string json = $@"{{
  ""id"": ""{id}"",
  ""summary"": ""test advisory""{aliasBlock},
  ""affected"": [{{
    ""package"": {{ ""ecosystem"": ""{ecosystem}"", ""name"": ""{name}"" }},
    ""versions"": [{string.Join(",", versions.Select(v => $"\"{v}\""))}]
  }}]{sevBlock}
}}";
        // Advisory IDs like "RLSA-2024:1234" carry a colon, which is not a valid filename
        // character on some filesystems — the dump directory's filenames are never significant
        // to LocalOsvSource, so sanitize purely for the write.
        string safeFileName = id.Replace(':', '_');
        File.WriteAllText(Path.Combine(_dir, $"{safeFileName}.json"), json);
    }

    private LocalOsvSource Build() => new(_dir, NullLogger<LocalOsvSource>.Instance);

    [Fact]
    public async Task Query_HitOnVersion_ReturnsAdvisory()
    {
        WriteAdvisory("GHSA-1", "npm", "lodash", ["4.17.20", "4.17.21"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.21");
        Assert.Single(hits);
        Assert.Equal("GHSA-1", hits[0].Id);
        Assert.True(hits[0].IsHydrated);
    }

    [Fact]
    public async Task Query_VersionMiss_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-2", "npm", "lodash", ["4.17.20"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.21");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_NameMiss_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-3", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/ghost@1.0.0");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_EcosystemCaseInsensitive()
    {
        // OSV uses "PyPI" / "npm" / "NuGet"; PURLs use lowercase. Match both.
        WriteAdvisory("GHSA-4", "PyPI", "requests", ["2.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:pypi/requests@2.0.0");
        Assert.Single(hits);
    }

    [Fact]
    public async Task Query_CvssScoreParsedFromAdvisory()
    {
        WriteAdvisory("GHSA-5", "npm", "lodash", ["4.17.20"],
            severity: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@4.17.20");
        Assert.Single(hits);
        Assert.Equal("CRITICAL", hits[0].Severity);
        Assert.NotNull(hits[0].CvssScore);
    }

    [Fact]
    public async Task QueryBatch_ParallelToInputs_PreservesOrder()
    {
        WriteAdvisory("GHSA-A", "npm", "lodash", ["4.17.20"]);
        WriteAdvisory("GHSA-B", "npm", "react", ["18.0.0"]);
        var src = Build();

        var results = await src.QueryBatchAsync([
            "pkg:npm/react@18.0.0",
            "pkg:npm/ghost@1.0.0",
            "pkg:npm/lodash@4.17.20"
        ]);

        Assert.Equal(3, results.Count);
        Assert.Equal("GHSA-B", results[0][0].Id);
        Assert.Empty(results[1]);
        Assert.Equal("GHSA-A", results[2][0].Id);
    }

    [Fact]
    public async Task Query_MissingDirectory_EmptyResults()
    {
        Directory.Delete(_dir, recursive: true);
        var src = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);
        var hits = await src.QueryAsync("pkg:npm/lodash@1.0.0");
        Assert.Empty(hits);
    }

    // ── TryQueryAsync (reachability signal for PackageLookupService) ───────────

    [Fact]
    public async Task TryQueryAsync_DirectoryPresent_GenuinelyEmpty_ReportsReached()
    {
        // No advisory files at all, but the configured directory exists and was consulted —
        // this is the "genuinely clean" case, distinct from a misconfigured/unavailable source.
        var src = Build();

        var result = await src.TryQueryAsync("pkg:npm/lodash@1.0.0");

        Assert.True(result.Reached);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task TryQueryAsync_DirectoryPresent_WithHit_ReportsReached()
    {
        WriteAdvisory("GHSA-RCH", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        var result = await src.TryQueryAsync("pkg:npm/lodash@1.0.0");

        Assert.True(result.Reached);
        Assert.Single(result.Advisories);
    }

    [Fact]
    public async Task TryQueryAsync_MissingDirectory_ReportsUnreached()
    {
        // OSV_LOCAL_PATH missing/misconfigured — the only case that must NOT be read as "OSV
        // consulted, nothing found". Mirrors OsvClient's outage-detection contract offline.
        Directory.Delete(_dir, recursive: true);
        var src = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);

        var result = await src.TryQueryAsync("pkg:npm/lodash@1.0.0");

        Assert.False(result.Reached);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task Query_MalformedJson_SkippedNotThrown()
    {
        File.WriteAllText(Path.Combine(_dir, "bad.json"), "{not json");
        WriteAdvisory("GHSA-OK", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:npm/lodash@1.0.0");
        Assert.Single(hits);
        Assert.Equal("GHSA-OK", hits[0].Id);
    }

    [Fact]
    public async Task Query_MalformedPurl_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-Z", "npm", "lodash", ["1.0.0"]);
        var src = Build();

        Assert.Empty(await src.QueryAsync("not-a-purl"));
        Assert.Empty(await src.QueryAsync("pkg:npm/lodash"));      // no version
        Assert.Empty(await src.QueryAsync("pkg:npmlodash@1.0.0")); // no slash
    }

    // ── apk / Alpine ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Query_Apk_ReleaseQualifiedAdvisory_MatchesBareAlpineQuery()
    {
        // OSV publishes one release-qualified ecosystem per Alpine release; apk purls carry no
        // release qualifier, so a v3.18-qualified advisory must still be found.
        WriteAdvisory("CVE-Alpine-1", "Alpine:v3.18", "curl", ["8.9.0-r0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:apk/alpine/curl@8.9.0-r0?arch=x86_64");
        Assert.Single(hits);
        Assert.Equal("CVE-Alpine-1", hits[0].Id);
    }

    [Fact]
    public async Task Query_Apk_AcrossMultipleReleases_AllAreFound()
    {
        // Two different releases each carry a distinct advisory for the same package name —
        // both must be reachable via the single bare-"Alpine" query (the dual-bucket index).
        WriteAdvisory("CVE-Alpine-v318", "Alpine:v3.18", "openssl", ["3.1.0-r0"]);
        WriteAdvisory("CVE-Alpine-v319", "Alpine:v3.19", "openssl", ["3.1.0-r0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:apk/alpine/openssl@3.1.0-r0?arch=aarch64");
        var ids = hits.Select(h => h.Id).ToHashSet();
        Assert.Equal(2, hits.Count);
        Assert.Contains("CVE-Alpine-v318", ids);
        Assert.Contains("CVE-Alpine-v319", ids);
    }

    [Fact]
    public async Task Query_Apk_VersionMiss_ReturnsEmpty()
    {
        WriteAdvisory("CVE-Alpine-2", "Alpine:v3.18", "curl", ["8.8.0-r0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:apk/alpine/curl@8.9.0-r0?arch=x86_64");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_Apk_NameMiss_ReturnsEmpty()
    {
        WriteAdvisory("CVE-Alpine-3", "Alpine:v3.18", "curl", ["8.9.0-r0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:apk/alpine/wget@8.9.0-r0?arch=x86_64");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_Apk_DoesNotMatchUnrelatedEcosystem()
    {
        // A non-Alpine "curl" advisory (e.g. an npm namesake) must not leak into apk results —
        // MatchesEcosystemAndName's release-qualified prefix branch only fires for "Alpine".
        WriteAdvisory("GHSA-NotAlpine", "npm", "curl", ["8.9.0-r0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:apk/alpine/curl@8.9.0-r0?arch=x86_64");
        Assert.Empty(hits);
    }

    // ── Maven ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Query_Maven_ColonSeparatedOsvName_MatchesSlashSeparatedPurl()
    {
        // OSV mandates Maven names as "groupId:artifactId"; PurlNormalizer emits
        // pkg:maven/{groupId}/{artifactId}@{version}. The slash-to-colon conversion in ParsePurl
        // is what lets the slash-form purl hit the colon-keyed index.
        WriteAdvisory("GHSA-Maven-1", "Maven", "com.fasterxml.jackson.core:jackson-databind",
            ["2.9.9"]);
        var src = Build();

        var hits = await src.QueryAsync(
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9");
        Assert.Single(hits);
        Assert.Equal("GHSA-Maven-1", hits[0].Id);
    }

    [Fact]
    public async Task Query_Maven_VersionMiss_ReturnsEmpty()
    {
        WriteAdvisory("GHSA-Maven-2", "Maven", "org.apache.logging.log4j:log4j-core", ["2.14.0"]);
        var src = Build();

        var hits = await src.QueryAsync(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
        Assert.Empty(hits);
    }

    // ── Go ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Query_Golang_BareOsvVersion_MatchesVPrefixedPurl()
    {
        // OSV's Go entries express versions bare; PurlNormalizer.Golang carries the wire-form
        // "v" prefix into the purl. Stripping it in ParsePurl is what lets the two meet.
        WriteAdvisory("GHSA-Go-1", "Go", "golang.org/x/net", ["0.10.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:golang/golang.org/x/net@v0.10.0");
        Assert.Single(hits);
        Assert.Equal("GHSA-Go-1", hits[0].Id);
    }

    [Fact]
    public async Task Query_Golang_VPrefixedOsvVersion_MatchesVPrefixedPurl()
    {
        // The advisory side is stripped too, so a dump that does carry the prefix still matches
        // rather than silently missing.
        WriteAdvisory("GHSA-Go-2", "Go", "github.com/gorilla/websocket", ["v1.4.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:golang/github.com/gorilla/websocket@v1.4.0");
        Assert.Single(hits);
        Assert.Equal("GHSA-Go-2", hits[0].Id);
    }

    [Fact]
    public async Task Query_Golang_VersionMiss_ReturnsEmpty()
    {
        // Stripping the prefix must not collapse distinct versions into a match.
        WriteAdvisory("GHSA-Go-3", "Go", "golang.org/x/crypto", ["0.16.0"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:golang/golang.org/x/crypto@v0.17.0");
        Assert.Empty(hits);
    }

    // ── RPM (distro dual-bucket indexing) ───────────────────────────────────────
    // OSV has no single "RPM" ecosystem — advisories are filed under distro-specific,
    // release-qualified names (Rocky Linux, AlmaLinux, Red Hat, …). These pin the fix for #608:
    // a realistic distro-filed advisory (Rocky Linux/AlmaLinux ID shape, aliased to a CVE) must
    // be found by a bare pkg:rpm query, mirroring how Alpine's dual-bucket index already works.

    [Fact]
    public async Task Query_Rpm_RockyLinuxAdvisory_MatchesBareRpmQuery()
    {
        WriteAdvisory(
            "RLSA-2024:1234", "Rocky Linux:9", "tree", ["1.8.0-3.el9"],
            aliases: ["CVE-2024-12345"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:rpm/tree@1.8.0-3.el9?arch=x86_64");

        Assert.Single(hits);
        Assert.Equal("RLSA-2024:1234", hits[0].Id);
        Assert.Contains("CVE-2024-12345", hits[0].Aliases);
    }

    [Fact]
    public async Task Query_Rpm_AlmaLinuxAdvisory_MatchesBareRpmQuery()
    {
        WriteAdvisory(
            "ALSA-2024:5678", "AlmaLinux:9", "openssl", ["3.0.7-27.el9_4"],
            aliases: ["CVE-2024-56789"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:rpm/openssl@3.0.7-27.el9_4?arch=x86_64");

        Assert.Single(hits);
        Assert.Equal("ALSA-2024:5678", hits[0].Id);
    }

    [Fact]
    public async Task Query_Rpm_VersionOutsideAdvisoryRange_ReturnsEmpty()
    {
        // The dual-bucket indexing must not turn version matching into a rubber stamp — a real
        // distro advisory that does not cover the artefact's specific version is still a miss.
        WriteAdvisory(
            "RLSA-2024:1111", "Rocky Linux:9", "tree", ["1.8.0-3.el9"],
            aliases: ["CVE-2024-11111"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:rpm/tree@1.9.0-1.el9?arch=x86_64");

        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_Rpm_NameMiss_ReturnsEmpty()
    {
        WriteAdvisory("RLSA-2024:2222", "Rocky Linux:9", "tree", ["1.8.0-3.el9"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:rpm/wget@1.8.0-3.el9?arch=x86_64");
        Assert.Empty(hits);
    }

    [Fact]
    public async Task Query_Rpm_DoesNotMatchNonRpmDistro()
    {
        // Debian (dpkg) is not an RPM-packaged distro — a Debian advisory sharing a package name
        // must not leak into an RPM query's results the way it would if this were a blanket
        // prefix match rather than the known-distro-name check.
        WriteAdvisory("DSA-2024-1", "Debian:12", "tree", ["1.8.0-3"]);
        var src = Build();

        var hits = await src.QueryAsync("pkg:rpm/tree@1.8.0-3?arch=x86_64");
        Assert.Empty(hits);
    }

    // ── RPM (HasCoverageFor — the dynamic per-source coverage signal) ──────────

    [Fact]
    public async Task HasCoverageFor_Rpm_NoDistroAdvisoriesInDump_ReturnsFalse()
    {
        // The dump loaded fine but carries nothing an RPM query could ever match against —
        // stamping vuln_checked_at off that would be the exact false-clean #608 describes.
        WriteAdvisory("GHSA-Unrelated", "npm", "left-pad", ["1.0.0"]);
        var src = Build();
        await src.QueryAsync("pkg:npm/left-pad@1.0.0"); // trigger the initial load

        Assert.False(await src.HasCoverageFor("rpm"));
    }

    [Fact]
    public async Task HasCoverageFor_Rpm_EmptyDump_ReturnsFalse()
    {
        var src = Build();
        Assert.False(await src.HasCoverageFor("rpm"));
    }

    [Fact]
    public async Task HasCoverageFor_Rpm_WithDistroAdvisories_ReturnsTrue()
    {
        // Coverage is about the ecosystem having *any* distro feed loaded, not about this one
        // artefact's own package having a hit — that is exactly the "scanned and genuinely
        // clean" case, which must still be reported as covered.
        WriteAdvisory("RLSA-2024:3333", "Rocky Linux:9", "tree", ["1.8.0-3.el9"]);
        var src = Build();

        Assert.True(await src.HasCoverageFor("rpm"));
    }

    [Fact]
    public async Task HasCoverageFor_MissingDirectory_Rpm_ReturnsFalse()
    {
        Directory.Delete(_dir, recursive: true);
        var src = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);

        Assert.False(await src.HasCoverageFor("rpm"));
    }

    [Fact]
    public async Task HasCoverageFor_NonRpmEcosystemWithFeed_AlwaysTrue()
    {
        var src = Build();
        Assert.True(await src.HasCoverageFor("npm"));
    }

    [Fact]
    public async Task HasCoverageFor_StaticNoFeedEcosystem_ReturnsFalse()
    {
        // The static OsvFeedCoverage.HasAdvisoryFeed gate is consulted first and is never
        // widened by anything loaded in the dump.
        WriteAdvisory("GHSA-Terraform", "npm", "left-pad", ["1.0.0"]);
        var src = Build();

        Assert.False(await src.HasCoverageFor("terraform"));
    }
}
