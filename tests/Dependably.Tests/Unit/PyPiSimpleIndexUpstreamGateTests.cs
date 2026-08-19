using System.Text.Json;
using Dependably.Api.PyPiProtocol;
using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The simple index must never advertise a file its download path refuses. The local half of that
/// rule was already enforced; these tests cover the two ways it was still breakable — an upstream
/// entry nobody has fetched, and an upstream entry that re-advertises a filename the gate just
/// removed from the local side.
///
/// Every test here fails on the pre-fix renderer, which is the point: the previous suite only ever
/// blocked a local version whose filename was absent from the upstream list, so the collision that
/// defeats the filter was never constructed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PyPiSimpleIndexUpstreamGateTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 18, 12, 0, 0, TimeSpan.Zero);

    // ── The collision: a blocked local version re-advertised by its upstream twin ──────────

    /// <summary>
    /// The regression that made the local filter defeatable. A hard-blocked version's filename was
    /// never claimed, so the upstream merge added it straight back — and for a proxied package the
    /// same filename is upstream almost by definition, which is why this was not an edge case.
    ///
    /// Blocking must suppress a filename, not merely decline to emit it.
    /// </summary>
    [Fact]
    public void BlockedLocalVersion_WhoseFilenameIsAlsoUpstream_IsAbsentFromBothRenderings()
    {
        const string blockedFile = "demo-4.0.0.tar.gz";
        const string localSha = "7777777777777777777777777777777777777777777777777777777777777777";
        const string upstreamSha = "8888888888888888888888888888888888888888888888888888888888888888";

        var blocked = Version("v4", "4.0.0", blockedFile, localSha);
        blocked.ManualBlockState = "blocked";

        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new(blockedFile, upstreamSha),
        };
        var files = new[] { File("f4", "v4", blockedFile, localSha, 400) }.ToLookup(f => f.PackageVersionId);

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstream, [blocked], files, Settings(), NoSignals(), Now);
        string json = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstream, [blocked], files, Settings(), NoSignals(), Now);

        Assert.DoesNotContain(blockedFile, html, StringComparison.Ordinal);
        Assert.DoesNotContain(blockedFile, json, StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamSha, html, StringComparison.Ordinal);
        Assert.DoesNotContain(upstreamSha, json, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same hole through the version-row branch: a synthetic proxy projection carries its one
    /// artifact on the version row rather than in the file lookup, so the claim has to happen on
    /// that path too, not only on the per-file one.
    /// </summary>
    [Fact]
    public void BlockedVersionWithNoFileRows_StillClaimsItsFilenameAgainstTheUpstreamMerge()
    {
        const string blockedFile = "demo-3.0.0.tar.gz";
        var blocked = Version("v3", "3.0.0", blockedFile, "6666666666666666666666666666666666666666666666666666666666666666");
        blocked.ManualBlockState = "blocked";

        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry> { new(blockedFile, null) };

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstream, [blocked], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);

        Assert.DoesNotContain(blockedFile, html, StringComparison.Ordinal);
    }

    // ── Upstream-only entries: the arms an index can actually decide ───────────────────────

    /// <summary>
    /// The reported failure, at the renderer. A release younger than the org's cooldown is not
    /// advertised, so a resolver never selects a coordinate the download path would refuse — and
    /// an older release of the same package stays available to resolve to instead.
    /// </summary>
    [Fact]
    public void UpstreamOnlyEntry_YoungerThanTheHold_IsNotAdvertised_WhileTheOlderOneIs()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("idna-3.19-py3-none-any.whl", "aaaa", UploadTime: Now.AddHours(-2)),
            new("idna-3.18-py3-none-any.whl", "bbbb", UploadTime: Now.AddDays(-60)),
        };

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "idna", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(minReleaseAgeHours: 24), NoSignals(), Now);

        Assert.DoesNotContain("idna-3.19", html, StringComparison.Ordinal);
        Assert.Contains("idna-3.18", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The control that keeps the filter honest: with no cooldown configured, the same too-young
    /// entry is advertised. Without this, a renderer that dropped every upstream entry would pass
    /// the test above.
    /// </summary>
    [Fact]
    public void UpstreamOnlyEntry_WithNoHoldConfigured_IsAdvertised()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("idna-3.19-py3-none-any.whl", "aaaa", UploadTime: Now.AddHours(-2)),
        };

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "idna", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);

        Assert.Contains("idna-3.19", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// An upstream that speaks only PEP 503 supplies no upload time, and an unknown publish time
    /// fails the hold open rather than hiding the package — the same posture the gate itself takes
    /// for a null publish timestamp. Failing closed here would empty the index for every HTML-only
    /// upstream the moment a tenant enabled a cooldown.
    /// </summary>
    [Fact]
    public void UpstreamOnlyEntry_WithNoUploadTime_FailsOpen()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("idna-3.19-py3-none-any.whl", "aaaa"),
        };

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "idna", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(minReleaseAgeHours: 24), NoSignals(), Now);

        Assert.Contains("idna-3.19", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// PyPI spells deprecation as a yank, and the download path already gates on it, so the index
    /// has to as well or the two disagree on an upstream-only coordinate.
    /// </summary>
    [Fact]
    public void UpstreamOnlyEntry_Yanked_IsNotAdvertisedUnderABlockingDeprecationPolicy()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("demo-1.0.0.tar.gz", "aaaa", Yanked: true, YankReason: "broken sdist"),
            new("demo-1.0.1.tar.gz", "bbbb"),
        };

        var settings = Settings();
        settings.BlockDeprecated = "block_all";

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, settings, NoSignals(), Now);

        Assert.DoesNotContain("demo-1.0.0.tar.gz", html, StringComparison.Ordinal);
        Assert.Contains("demo-1.0.1.tar.gz", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// Under a non-blocking policy a yanked upstream file stays listed, but it has to be listed
    /// AS yanked. Advertising it as clean is a PEP 592 violation independent of the gate: pip only
    /// avoids a yanked file when it can see the flag, so the flag going missing silently re-selects
    /// the release the publisher withdrew.
    /// </summary>
    [Fact]
    public void UpstreamOnlyEntry_Yanked_IsAdvertisedAsYankedInBothRenderings()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("demo-1.0.0.tar.gz", "aaaa", Yanked: true, YankReason: "broken sdist"),
        };

        string html = PyPiSimpleIndexHelper.RenderMergedSimpleIndex(
            "demo", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);
        string json = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);

        Assert.Contains("data-yanked=\"broken sdist\"", html, StringComparison.Ordinal);

        using var doc = JsonDocument.Parse(json);
        var file = doc.RootElement.GetProperty("files").EnumerateArray().Single();
        Assert.Equal("broken sdist", file.GetProperty("yanked").GetString());
    }

    // ── PEP 691 parsing ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// PEP 691 carries a yank three ways in one member, and the string form is the common spelling
    /// on pypi.org. A reader that accepts only the boolean — as the legacy JSON-API reader does,
    /// correctly for that document's separate <c>yanked_reason</c> — silently treats every
    /// string-form yank as not yanked.
    /// </summary>
    [Theory]
    [InlineData("false", false, null)]
    [InlineData("true", true, null)]
    [InlineData("\"withdrawn: builds are broken\"", true, "withdrawn: builds are broken")]
    [InlineData("\"\"", true, null)]
    public void Pep691Parser_ReadsAllThreeYankedSpellings(string yankedJson, bool expectedYanked, string? expectedReason)
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson($$"""
            {"meta":{"api-version":"1.1"},"name":"demo","files":[
              {"filename":"demo-1.0.0.tar.gz","url":"https://x/demo-1.0.0.tar.gz",
               "hashes":{"sha256":"abc"},"yanked":{{yankedJson}}}
            ]}
            """);

        var entry = Assert.Single(entries);
        Assert.Equal(expectedYanked, entry.Yanked);
        Assert.Equal(expectedReason, entry.YankReason);
    }

    [Fact]
    public void Pep691Parser_ReadsUploadTimeSizeUrlAndDigest()
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson("""
            {"meta":{"api-version":"1.1"},"name":"idna","files":[
              {"filename":"idna-3.19.tar.gz","url":"https://files.pythonhosted.org/p/idna-3.19.tar.gz",
               "hashes":{"sha256":"deadbeef"},"size":190000,
               "upload-time":"2026-08-18T05:14:24.270231Z","yanked":false}
            ]}
            """);

        var entry = Assert.Single(entries);
        Assert.Equal("idna-3.19.tar.gz", entry.Filename);
        Assert.Equal("deadbeef", entry.Sha256);
        Assert.Equal("https://files.pythonhosted.org/p/idna-3.19.tar.gz", entry.Url);
        Assert.Equal(190000, entry.SizeBytes);
        Assert.Equal(new DateTimeOffset(2026, 8, 18, 5, 14, 24, 270, TimeSpan.Zero).AddTicks(2310), entry.UploadTime);
    }

    /// <summary>
    /// Upstream documents are semi-trusted: a wrong-typed or absent member degrades to "unknown"
    /// for that field alone, and an entry with no usable filename is dropped without taking the
    /// rest of the document with it.
    /// </summary>
    [Fact]
    public void Pep691Parser_DegradesPerMemberOnMalformedInput()
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson("""
            {"files":[
              {"filename":"good-1.0.0.tar.gz","hashes":"not-an-object","size":"big","upload-time":"not-a-date"},
              {"url":"https://x/no-filename.tar.gz"},
              {"filename":""},
              "not-an-object"
            ]}
            """);

        var entry = Assert.Single(entries);
        Assert.Equal("good-1.0.0.tar.gz", entry.Filename);
        Assert.Null(entry.Sha256);
        Assert.Null(entry.SizeBytes);
        Assert.Null(entry.UploadTime);
    }

    /// <summary>
    /// Which parser runs follows the response's declared content type, not the Accept we sent —
    /// an upstream is free to ignore content negotiation, and several do.
    /// </summary>
    [Theory]
    [InlineData("application/vnd.pypi.simple.v1+json")]
    [InlineData("application/vnd.pypi.simple.v1+json; charset=utf-8")]
    public void ParseUpstreamSimpleIndex_DispatchesOnDeclaredContentType(string contentType)
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndex(
            contentType,
            """{"files":[{"filename":"demo-1.0.0.tar.gz","hashes":{"sha256":"abc"}}]}""");

        Assert.Equal("demo-1.0.0.tar.gz", Assert.Single(entries).Filename);
    }

    [Fact]
    public void ParseUpstreamSimpleIndex_FallsBackToHtmlWhenUpstreamIgnoresTheAccept()
    {
        var entries = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndex(
            "text/html",
            """<a href="https://x/demo-1.0.0.tar.gz#sha256=abc">demo-1.0.0.tar.gz</a>""");

        Assert.Equal("demo-1.0.0.tar.gz", Assert.Single(entries).Filename);
    }

    /// <summary>
    /// A body that claims to be PEP 691 and is not must reach the caller's per-source catch, which
    /// moves to the next upstream and then to local-only. Returning an empty list instead would
    /// render as "this package has no files" — a worse answer than falling back, and one a client
    /// cannot tell from the truth.
    /// </summary>
    [Fact]
    public void ParseUpstreamSimpleIndex_MalformedJsonThrowsRatherThanAdvertisingNothing()
    {
        Assert.ThrowsAny<JsonException>(() =>
            PyPiSimpleIndexHelper.ParseUpstreamSimpleIndex(
                PyPiSimpleIndexHelper.JsonContentType, "{\"files\": [ truncated"));
    }

    // ── Emitting PEP 700, so the fix composes across chained instances ─────────────────────

    /// <summary>
    /// A downstream dependably or edge node negotiating JSON from here needs an upload time to
    /// apply its own hold to entries it has not fetched. Without this the fix stops at the first
    /// hop, and the release-age arm silently fails open on every chained deployment.
    /// </summary>
    [Fact]
    public void RenderedJson_CarriesUploadTime_SoADownstreamInstanceCanApplyItsOwnHold()
    {
        var upstream = new List<PyPiSimpleIndexHelper.UpstreamSimpleIndexEntry>
        {
            new("demo-9.9.9.tar.gz", "aaaa", UploadTime: Now.AddDays(-3)),
        };

        string json = PyPiSimpleIndexHelper.RenderMergedSimpleIndexJson(
            "demo", upstream, [], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);

        var reparsed = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson(json);
        Assert.Equal(Now.AddDays(-3), Assert.Single(reparsed).UploadTime);
    }

    /// <summary>
    /// A locally uploaded version has no upstream publish timestamp by construction, so its own
    /// ingest time is what it was published at as far as this index is concerned. Emitting nothing
    /// would make a downstream instance's hold fail open on everything hosted here.
    ///
    /// The time is taken per file rather than per version, because PEP 700's member is per file
    /// and a version's distributions genuinely can be uploaded at different times — a later
    /// platform wheel added to an existing release.
    /// </summary>
    [Fact]
    public void RenderedJson_CarriesEachHostedFilesOwnUploadTime()
    {
        var hosted = Version("v1", "1.0.0", "demo-1.0.0.tar.gz", "aaaa");
        var files = new[]
        {
            new PackageVersionFile("f1", "v1", "o1", "demo-1.0.0.tar.gz", "k1", 100, "aaaa", Now.AddDays(-10)),
            new PackageVersionFile("f2", "v1", "o1", "demo-1.0.0-py3-none-any.whl", "k2", 200, "bbbb", Now.AddDays(-2)),
        }.ToLookup(f => f.PackageVersionId);

        string json = PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(
            "demo", [hosted], files, Settings(), NoSignals(), Now);

        var byName = PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson(json).ToDictionary(e => e.Filename);
        Assert.Equal(Now.AddDays(-10), byName["demo-1.0.0.tar.gz"].UploadTime);
        Assert.Equal(Now.AddDays(-2), byName["demo-1.0.0-py3-none-any.whl"].UploadTime);
    }

    /// <summary>
    /// A cached proxy version carries the upstream's own publish timestamp, and that is what must
    /// be advertised — not the moment this instance happened to fetch it. Emitting the local fetch
    /// time would reset every downstream instance's cooldown clock to zero on adoption, turning a
    /// hold on the original release date into a hold on the mirror date.
    /// </summary>
    [Fact]
    public void RenderedJson_PrefersTheUpstreamPublishTimeOverLocalIngestTime()
    {
        var proxied = Version("v1", "1.0.0", "demo-1.0.0.tar.gz", "aaaa");
        proxied.Origin = "proxy";
        proxied.PublishedAt = Now.AddDays(-30);
        proxied.CreatedAt = Now.AddMinutes(-5);

        string json = PyPiSimpleIndexHelper.RenderLocalSimpleIndexJson(
            "demo", [proxied], PyPiSimpleIndexHelper.NoHostedFiles, Settings(), NoSignals(), Now);

        Assert.Equal(Now.AddDays(-30), Assert.Single(PyPiSimpleIndexHelper.ParseUpstreamSimpleIndexJson(json)).UploadTime);
    }

    // ── Fixtures ──────────────────────────────────────────────────────────────────────────

    private static OrgSettings Settings(int? minReleaseAgeHours = null) =>
        new() { AnonymousPull = true, MinReleaseAgeHours = minReleaseAgeHours };

    private static Dictionary<string, VulnGateSignals> NoSignals() => [];

    private static PackageVersion Version(string id, string version, string filename, string sha256) => new()
    {
        Id = id,
        PackageId = "p1",
        Version = version,
        Purl = $"pkg:pypi/demo@{version}",
        BlobKey = $"hosted/o1/pypi/demo/{version}/{filename}",
        Filename = filename,
        ChecksumSha256 = sha256,
        Origin = "uploaded",
        CreatedAt = DateTimeOffset.UnixEpoch,
    };

    private static PackageVersionFile File(string id, string versionId, string filename, string sha256, long sizeBytes)
        => new(id, versionId, "o1", filename, $"hosted/o1/pypi/demo/{filename}", sizeBytes, sha256,
            DateTimeOffset.UnixEpoch);
}
