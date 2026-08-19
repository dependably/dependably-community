using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Integration;

/// <summary>
/// Coverage for <c>POST /npm/-/npm/v1/security/advisories/bulk</c> — the only audit request npm 7
/// and newer make (<c>@npmcli/arborist</c>'s audit report has a single request path and no
/// quick-audit fallback). The endpoint projects the registry's OSV-backed advisory data into npm's
/// wire format.
///
/// The stub source answers with an advisory for <b>every</b> version of a package it knows about,
/// regardless of version. That is not a convenience — it mirrors <c>LocalOsvSource</c>, which
/// matches only enumerated <c>versions[]</c> and deliberately returns range-only advisories for
/// every version of a package. The handler's own interval evaluation is what keeps a patched
/// version out of the report, so testing against a version-blind source is what actually exercises
/// it.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmAuditBulkAdvisoriesTests
{
    private const string BulkPath = "/npm/-/npm/v1/security/advisories/bulk";

    // A scored advisory: lodash prototype pollution, affected [4.0.0, 4.17.21).
    // The CVSS vector scores 9.8 → CRITICAL → npm "critical".
    private static OsvAdvisory LodashAdvisory() => BuildAdvisory(
        id: "GHSA-jf85-cpcp-j695",
        summary: "Prototype Pollution in lodash",
        severity: "CRITICAL",
        cvssScore: 9.8,
        rawJson: """
        {
          "id": "GHSA-jf85-cpcp-j695",
          "summary": "Prototype Pollution in lodash",
          "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
          ],
          "affected": [
            {
              "package": { "ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash" },
              "ranges": [
                { "type": "SEMVER", "events": [ { "introduced": "4.0.0" }, { "fixed": "4.17.21" } ] }
              ]
            }
          ],
          "database_specific": { "cwe_ids": [ "CWE-1321" ] }
        }
        """);

    // A scoped package's advisory, affected [1.0.0, 1.2.0).
    private static OsvAdvisory ScopedAdvisory() => BuildAdvisory(
        id: "GHSA-scope-test-0001",
        summary: "Command injection in @acme/widget",
        severity: "HIGH",
        cvssScore: 8.1,
        rawJson: """
        {
          "id": "GHSA-scope-test-0001",
          "summary": "Command injection in @acme/widget",
          "severity": [
            { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" }
          ],
          "affected": [
            {
              "package": {
                "ecosystem": "npm", "name": "@acme/widget", "purl": "pkg:npm/%40acme/widget"
              },
              "ranges": [
                { "type": "SEMVER", "events": [ { "introduced": "1.0.0" }, { "fixed": "1.2.0" } ] }
              ]
            }
          ]
        }
        """);

    // The stub /querybatch leaves behind when hydration is capped or GET /vulns/{id} fails: the id
    // is known and OSV matched it to the purl, but no schema data arrived (IsHydrated=false).
    private static OsvAdvisory UnhydratedAdvisory() => new(
        Id: "GHSA-unhydrated-0001",
        Aliases: [],
        Summary: null,
        Severity: null,
        CvssScore: null,
        AffectedPackages: [],
        Published: null,
        Modified: null,
        IsHydrated: false,
        RawJson: null);

    // An advisory OSV never scored: no severity[] block, no database_specific.severity.
    private static OsvAdvisory UnscoredAdvisory() => BuildAdvisory(
        id: "GHSA-unscored-0001",
        summary: "Unreviewed report affecting nostring",
        severity: null,
        cvssScore: null,
        rawJson: """
        {
          "id": "GHSA-unscored-0001",
          "summary": "Unreviewed report affecting nostring",
          "affected": [
            {
              "package": { "ecosystem": "npm", "name": "nostring", "purl": "pkg:npm/nostring" },
              "ranges": [
                { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ] }
              ]
            }
          ]
        }
        """);

    /// <summary>
    /// A package with a known advisory is reported, with npm's exact field names and a
    /// <c>vulnerable_versions</c> range rendered from the OSV interval.
    /// </summary>
    [Fact]
    public async Task PackageWithAdvisory_IsReportedInNpmWireFormat()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["lodash"] = ["4.17.20"] });

        var advisories = report.RootElement.GetProperty("lodash");
        Assert.Equal(1, advisories.GetArrayLength());

        var advisory = advisories[0];
        Assert.Equal("GHSA-jf85-cpcp-j695", advisory.GetProperty("id").GetString());
        Assert.Equal("critical", advisory.GetProperty("severity").GetString());
        Assert.Equal("Prototype Pollution in lodash", advisory.GetProperty("title").GetString());

        // snake_case on the wire — npm reads `vulnerable_versions`, never `vulnerableVersions`.
        Assert.Equal(">=4.0.0 <4.17.21", advisory.GetProperty("vulnerable_versions").GetString());
        Assert.False(advisory.TryGetProperty("vulnerableVersions", out _));

        Assert.Equal("CWE-1321", advisory.GetProperty("cwe")[0].GetString());
        Assert.Equal(9.8, advisory.GetProperty("cvss").GetProperty("score").GetDouble());
        Assert.Equal(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            advisory.GetProperty("cvss").GetProperty("vectorString").GetString());
    }

    /// <summary>
    /// The regression that an off-by-one on the <c>fixed</c> boundary would cause: 4.17.21 is the
    /// fixed version, so the interval [4.0.0, 4.17.21) does not contain it. The source still
    /// returns the advisory (range-only advisories are version-blind), so this asserts the
    /// handler's own interval check excludes it — a patched install must not be flagged.
    /// </summary>
    [Fact]
    public async Task VersionExactlyAtFixedBoundary_IsNotReported()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["lodash"] = ["4.17.21"] });

        Assert.Empty(report.RootElement.EnumerateObject());
    }

    /// <summary>The version immediately below the fix is still inside the interval.</summary>
    [Fact]
    public async Task VersionJustBelowFixedBoundary_IsReported()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["lodash"] = ["4.17.20"] });

        Assert.True(report.RootElement.TryGetProperty("lodash", out _));
    }

    /// <summary>
    /// A clean package is omitted from the response entirely — not returned with an empty array.
    /// npm iterates <c>Object.entries()</c> over the report, so an empty array would still create
    /// a (meaningless) entry; registry.npmjs.org omits clean packages and so does this.
    /// </summary>
    [Fact]
    public async Task CleanPackage_IsOmittedEntirelyNotEmptyArray()
    {
        await using var factory = await FactoryWithAsync();
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["left-pad"] = ["1.3.0"] });

        Assert.False(report.RootElement.TryGetProperty("left-pad", out _));
        Assert.Empty(report.RootElement.EnumerateObject());
    }

    /// <summary>
    /// The mixed case: one bulk request naming vulnerable and clean packages together. Batch
    /// endpoints have to be tested for partial results, not just all-hit and all-clean — a
    /// grouping bug that drops or over-reports only shows up when both kinds share a call.
    /// </summary>
    [Fact]
    public async Task MixedRequest_ReportsOnlyVulnerablePackages()
    {
        await using var factory = await FactoryWithAsync(
            ("lodash", LodashAdvisory()),
            ("@acme/widget", ScopedAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new()
        {
            ["lodash"] = ["4.17.20"],        // vulnerable
            ["left-pad"] = ["1.3.0"],        // clean
            ["@acme/widget"] = ["1.1.0"],    // vulnerable, scoped
            ["express"] = ["4.18.2"],        // clean
        });

        var keys = report.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet();
        Assert.Equal(new HashSet<string> { "lodash", "@acme/widget" }, keys);
    }

    /// <summary>
    /// A single request where one version of a package is vulnerable and another is already
    /// patched: the package is reported (for the vulnerable version) and the advisory is listed
    /// once, not once per version.
    /// </summary>
    [Fact]
    public async Task MixedVersionsOfOnePackage_ReportsAdvisoryOnce()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["lodash"] = ["4.17.20", "4.17.21"] });

        var advisories = report.RootElement.GetProperty("lodash");
        Assert.Equal(1, advisories.GetArrayLength());
        Assert.Equal("GHSA-jf85-cpcp-j695", advisories[0].GetProperty("id").GetString());
    }

    /// <summary>
    /// A scoped package (<c>@scope/name</c>) resolves through purl construction and OSV name
    /// matching, and comes back keyed by the exact name npm sent — npm re-queries its own tree by
    /// that key, so any re-spelling would silently drop the result.
    /// </summary>
    [Fact]
    public async Task ScopedPackage_ResolvesAndKeysByRequestedName()
    {
        await using var factory = await FactoryWithAsync(("@acme/widget", ScopedAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["@acme/widget"] = ["1.1.0"] });

        var advisories = report.RootElement.GetProperty("@acme/widget");
        Assert.Equal("GHSA-scope-test-0001", advisories[0].GetProperty("id").GetString());
        Assert.Equal(">=1.0.0 <1.2.0", advisories[0].GetProperty("vulnerable_versions").GetString());
        Assert.Equal("high", advisories[0].GetProperty("severity").GetString());
    }

    /// <summary>
    /// An advisory OSV never scored is represented honestly: <c>info</c> (npm's lowest bucket,
    /// below the default audit-level of <c>low</c>) with a null CVSS score. It must not be
    /// defaulted to <c>low</c>, and it must not be left without a severity — metavuln-calculator
    /// turns a missing severity into <c>high</c>, inventing a rating outright. The null score
    /// matters too: 0 is a real CVSS value meaning "None".
    /// </summary>
    [Fact]
    public async Task UnscoredAdvisory_IsReportedAsInfoWithNullScore()
    {
        await using var factory = await FactoryWithAsync(("nostring", UnscoredAdvisory()));
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, new() { ["nostring"] = ["1.0.0"] });

        var advisory = report.RootElement.GetProperty("nostring")[0];
        Assert.Equal("info", advisory.GetProperty("severity").GetString());
        Assert.NotEqual("low", advisory.GetProperty("severity").GetString());

        var cvss = advisory.GetProperty("cvss");
        Assert.Equal(JsonValueKind.Null, cvss.GetProperty("score").ValueKind);
        Assert.Equal(JsonValueKind.Null, cvss.GetProperty("vectorString").ValueKind);

        // introduced:"0" renders as an upper bound only — never an empty string, which
        // metavuln-calculator would coerce to "*" and flag every version.
        Assert.Equal("<2.0.0", advisory.GetProperty("vulnerable_versions").GetString());
    }

    /// <summary>
    /// npm gzips the audit request body (npm-registry-fetch sets <c>Content-Encoding: gzip</c> and
    /// compresses the payload on every bulk audit call). ASP.NET Core does not decompress request
    /// bodies by default, so this is the shape the real client actually sends.
    /// </summary>
    [Fact]
    public async Task GzipEncodedRequestBody_IsDecompressedAndAudited()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = await AuthedClientAsync(factory);

        string json = JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] });
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            byte[] raw = Encoding.UTF8.GetBytes(json);
            await gzip.WriteAsync(raw);
        }

        using var content = new ByteArrayContent(compressed.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");

        var resp = await client.PostAsync(BulkPath, content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("lodash", out _));
    }

    /// <summary>An empty tree is a well-formed question whose answer is an empty report.</summary>
    [Fact]
    public async Task EmptyRequest_ReturnsEmptyReport()
    {
        await using var factory = await FactoryWithAsync();
        using var client = await AuthedClientAsync(factory);

        var report = await PostBulkAsync(client, []);

        Assert.Empty(report.RootElement.EnumerateObject());
    }

    /// <summary>A body that isn't the documented shape is rejected, not silently audited.</summary>
    [Fact]
    public async Task MalformedBody_Returns400()
    {
        await using var factory = await FactoryWithAsync();
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent("[\"not-an-object\"]", Encoding.UTF8, "application/json");
        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    /// <summary>
    /// The fan-out bound: a request naming more package-versions than the registry audits per
    /// request is refused with 413 before any advisory query is issued, rather than fanning out
    /// unboundedly. npm treats the non-2xx as a soft warning and continues the install.
    /// </summary>
    [Fact]
    public async Task RequestExceedingVersionCap_Returns413AndQueriesNothing()
    {
        var stub = new StubOsvSource([]);
        await using var factory = await FactoryWithStubAsync(stub);
        using var client = await AuthedClientAsync(factory);

        // 101 versions for one package exceeds the 100-versions-per-package ceiling.
        string[] versions = Enumerable.Range(0, 101).Select(i => $"1.0.{i}").ToArray();
        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["big"] = versions }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        Assert.Empty(stub.QueriedPurls);
    }

    /// <summary>
    /// A tree larger than one upstream batch is audited, not refused. This is the regression that
    /// made the endpoint useless in practice: the old 500-distinct-package ceiling 413'd any
    /// ordinary project — this repo's own frontend is 523 packages — and npm neither chunks nor
    /// retries on 413, so the caller got no advisory data at all rather than a partial report.
    ///
    /// 1500 packages spans two chunks and proves the seam: every package is queried, the advisory
    /// on a package in the SECOND chunk is reported (a first-chunk-only implementation returns 200
    /// with an empty body and looks like a pass), and the response is a real report.
    /// </summary>
    [Fact]
    public async Task TreeLargerThanOneUpstreamBatch_IsAuditedRatherThanRefused()
    {
        // The advisory sits on pkg-1200, which lands in the second chunk of 1000.
        var stub = new StubOsvSource(("pkg-1200", LodashAdvisory()));
        await using var factory = await FactoryWithStubAsync(stub);
        using var client = await AuthedClientAsync(factory);

        var payload = Enumerable.Range(0, 1500)
            .ToDictionary(i => $"pkg-{i}", _ => new[] { "4.0.0" });
        using var content = new StringContent(
            JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(1500, stub.QueriedPurls.Count);

        // Two upstream calls for 1500 pairs — the tree is split, not sent as one oversized batch
        // the source would reject, and not fanned out one call per package.
        Assert.Equal(2, stub.BatchCalls.Count);
        Assert.Equal([1000, 500], stub.BatchCalls);

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("pkg-1200", out var advisories),
            "the advisory on a second-chunk package must appear in the report");
        Assert.Equal(1, advisories.GetArrayLength());
    }

    /// <summary>
    /// The adversarial twin: a request beyond the endpoint's actual resource bound is still
    /// refused. The bound is total package-version pairs — cost the caller cannot reshape away —
    /// not a package count npm has no way to act on, and the refusal names the limit it hit.
    /// </summary>
    [Fact]
    public async Task RequestBeyondThePairBound_Returns413AndQueriesNothing()
    {
        var stub = new StubOsvSource([]);
        await using var factory = await FactoryWithStubAsync(stub);
        using var client = await AuthedClientAsync(factory);

        // 10 001 pairs: 1001 packages x 10 versions, one pair past the 10 000 ceiling.
        var payload = Enumerable.Range(0, 1001)
            .ToDictionary(
                i => $"pkg-{i}",
                _ => Enumerable.Range(0, 10).Select(v => $"1.0.{v}").ToArray());
        using var content = new StringContent(
            JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        Assert.Empty(stub.QueriedPurls);

        // problem+json naming the actual limit hit, so the refusal is actionable rather than opaque.
        string body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("10000", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Chunking must not weaken the never-fabricate-an-all-clear posture. When a LATER chunk cannot
    /// reach the advisory source, the whole request answers 503 — the packages in the earlier,
    /// successful chunk must not be reported as clean, which would be a partial all-clear dressed
    /// as a complete report.
    /// </summary>
    [Fact]
    public async Task UnreachableOnALaterChunk_Fails503RatherThanReportingTheEarlierChunkClean()
    {
        var stub = new StubOsvSource([]) { UnreachedFromBatch = 2 };
        await using var factory = await FactoryWithStubAsync(stub);
        using var client = await AuthedClientAsync(factory);

        var payload = Enumerable.Range(0, 1500)
            .ToDictionary(i => $"pkg-{i}", _ => new[] { "1.0.0" });
        using var content = new StringContent(
            JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>
    /// The endpoint queries the advisory source with canonical npm purls — including the scoped
    /// spelling <c>LocalOsvSource</c> parses via <c>LastIndexOf('@')</c>.
    /// </summary>
    [Fact]
    public async Task Query_UsesCanonicalNpmPurls()
    {
        var stub = new StubOsvSource([]);
        await using var factory = await FactoryWithStubAsync(stub);
        using var client = await AuthedClientAsync(factory);

        await PostBulkAsync(client, new()
        {
            ["lodash"] = ["4.17.20"],
            ["@acme/widget"] = ["1.1.0"],
        });

        Assert.Contains("pkg:npm/lodash@4.17.20", stub.QueriedPurls);
        Assert.Contains("pkg:npm/@acme/widget@1.1.0", stub.QueriedPurls);
    }

    /// <summary>
    /// The outage guarantee, driven through the <b>real</b> <c>OsvClient</c> against a dead OSV
    /// endpoint — no stub in the path.
    ///
    /// This is the shape of a genuine outage: <c>OsvClient.QueryBatchAsync</c> swallows a non-2xx
    /// into a full-length list of <i>empty</i> results and never throws, so an audit built on the
    /// plain batch query reports "found 0 vulnerabilities" for a tree it never actually checked.
    /// Only the reachability signal distinguishes that from a genuinely clean tree.
    /// </summary>
    [Fact]
    public async Task RealOsvClient_UpstreamDown_Returns503NotCleanReport()
    {
        // A standalone server, not the factory's own MockUpstream: OSV_BASE_URL has to be known at
        // construction, and pointing the client at one factory's mock while stubbing another's
        // leaves the stub dead and the assertion riding on WireMock's unmatched-request 404.
        using var osvServer = WireMockServer.Start();
        osvServer
            .Given(Request.Create().WithPath("/querybatch").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.InternalServerError));

        await using var factory = new DependablyFactory { OsvBaseUrl = osvServer.Urls[0] };
        await factory.InitializeAsync();

        using var client = await AuthedClientAsync(factory);
        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);

        // The 503 must come from the stubbed 500, not from the client never arriving: without this
        // the test would still pass if OSV_BASE_URL pointed somewhere else entirely.
        var batchRequests = osvServer.LogEntries
            .Where(e => e.RequestMessage?.Path == "/querybatch")
            .ToList();
        Assert.NotEmpty(batchRequests);
        Assert.All(batchRequests, e =>
            Assert.Equal("500", e.ResponseMessage?.StatusCode?.ToString()));
    }

    /// <summary>
    /// The same guarantee at the source contract, without HTTP: a source that answers every purl
    /// with an empty list and reports itself unreached — exactly what <c>OsvClient</c> produces on
    /// a network failure or non-2xx, and what <c>LocalOsvSource</c> produces when
    /// <c>OSV_LOCAL_PATH</c> is missing. The results are indistinguishable from a clean tree, so
    /// the endpoint must key off reachability alone.
    /// </summary>
    [Fact]
    public async Task UnreachableSource_ReturningEmptyResults_Returns503NotCleanReport()
    {
        await using var factory = await FactoryWithStubAsync(new UnreachableOsvSource());
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>A source that throws outright is still refused, not read as clean.</summary>
    [Fact]
    public async Task ThrowingSource_Returns503NotEmptyReport()
    {
        await using var factory = await FactoryWithStubAsync(new ThrowingOsvSource());
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>
    /// An advisory OSV matched to the purl but whose detail never arrived (the per-batch hydration
    /// cap, or a failed <c>GET /vulns/{id}</c>) leaves a non-hydrated stub. Skipping it would
    /// report the package clean — the same fabricated all-clear as answering an outage with an
    /// empty report, only narrower.
    /// </summary>
    [Fact]
    public async Task UnhydratedAdvisory_Returns503RatherThanReportingPackageClean()
    {
        await using var factory = await FactoryWithAsync(("lodash", UnhydratedAdvisory()));
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>
    /// The mixed hydration case in ONE call: one package's advisory hydrated, another's not. The
    /// report cannot be served — a 200 here would carry the hydrated finding while silently
    /// omitting the unhydrated one, which is the more dangerous answer precisely because it looks
    /// complete.
    /// </summary>
    [Fact]
    public async Task MixedHydration_InOneCall_RefusesRatherThanServingPartialReport()
    {
        await using var factory = await FactoryWithAsync(
            ("lodash", LodashAdvisory()),              // hydrated
            ("express", UnhydratedAdvisory()));        // stub only
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]>
            {
                ["lodash"] = ["4.17.20"],
                ["express"] = ["4.18.2"],
            }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>
    /// The batch contract is one result list per input purl, in order. A source that returns a
    /// short list would leave the unmatched tail silently reported as clean, so an incomplete
    /// result set is refused outright rather than answered partially.
    /// </summary>
    [Fact]
    public async Task IncompleteResultSet_Returns503RatherThanPartialReport()
    {
        await using var factory = await FactoryWithStubAsync(new ShortResultOsvSource());
        using var client = await AuthedClientAsync(factory);

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]>
            {
                ["lodash"] = ["4.17.20"],
                ["express"] = ["4.18.2"],
            }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    /// <summary>
    /// The audit endpoint follows the same <c>AnonymousPull</c> gate as every other npm read path
    /// rather than inventing its own posture: with anonymous pull off (the default), an unauthed
    /// audit is refused with a Bearer challenge — it does not answer, and it does not leak whether
    /// any package exists.
    /// </summary>
    [Fact]
    public async Task AnonymousRequest_IsRefusedWhenAnonymousPullDisabled()
    {
        await using var factory = await FactoryWithAsync(("lodash", LodashAdvisory()));
        using var client = factory.CreateClient();

        using var content = new StringContent(
            JsonSerializer.Serialize(new Dictionary<string, string[]> { ["lodash"] = ["4.17.20"] }),
            Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Contains("Bearer", resp.Headers.WwwAuthenticate.ToString());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static async Task<HttpClient> AuthedClientAsync(DependablyFactory factory) =>
        factory.CreateClientWithBearer(await factory.CreateToken("pull"));

    private static async Task<DependablyFactory> FactoryWithAsync(
        params (string Name, OsvAdvisory Advisory)[] advisories)
        => await FactoryWithStubAsync(new StubOsvSource(advisories));

    private static async Task<DependablyFactory> FactoryWithStubAsync(IOsvSource source)
    {
        var factory = new DependablyFactory { OsvSource = source };
        await factory.InitializeAsync();
        return factory;
    }

    private static async Task<JsonDocument> PostBulkAsync(
        HttpClient client, Dictionary<string, string[]> body)
    {
        using var content = new StringContent(
            JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

        var resp = await client.PostAsync(BulkPath, content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        return JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
    }

    private static OsvAdvisory BuildAdvisory(
        string id, string summary, string? severity, double? cvssScore, string rawJson) =>
        new(
            Id: id,
            Aliases: [],
            Summary: summary,
            Severity: severity,
            CvssScore: cvssScore,
            AffectedPackages: [],
            Published: null,
            Modified: null,
            IsHydrated: true,
            RawJson: rawJson);

    /// <summary>
    /// Answers every query for a known package name with that package's advisory, regardless of
    /// the version in the purl — the version-blind behaviour <c>LocalOsvSource</c> exhibits for
    /// range-only advisories. Unknown packages answer empty.
    /// </summary>
    private sealed class StubOsvSource(params (string Name, OsvAdvisory Advisory)[] advisories) : IOsvSource
    {
        public List<string> QueriedPurls { get; } = [];

        /// <summary>
        /// One entry per upstream batch call, holding that call's purl count. A plain call counter
        /// would not tell a correctly chunked request apart from one fanned out a package at a
        /// time, which is the fan-out regression the chunking must not become.
        /// </summary>
        public List<int> BatchCalls { get; } = [];

        /// <summary>
        /// 1-based index of a batch call that reports the source as unreached, or null for none.
        /// Reproduces an outage that begins partway through a chunked request.
        /// </summary>
        public int? UnreachedFromBatch { get; init; }

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
        {
            QueriedPurls.Add(purl);
            return Task.FromResult(Answer(purl));
        }

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default)
        {
            BatchCalls.Add(purls.Count);
            var results = new List<List<OsvAdvisory>>(purls.Count);
            foreach (string purl in purls)
            {
                QueriedPurls.Add(purl);
                results.Add(Answer(purl));
            }
            return Task.FromResult(results);
        }

        // Overridden rather than left to the interface default so a nominated chunk can answer
        // with the production outage contract: full-length empty results, no throw, Reached=false.
        public async Task<OsvBatchQueryResult> TryQueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default)
        {
            if (UnreachedFromBatch is { } failing && BatchCalls.Count + 1 >= failing)
            {
                BatchCalls.Add(purls.Count);
                return new OsvBatchQueryResult(
                    purls.Select(_ => new List<OsvAdvisory>()).ToList(), Reached: false);
            }

            return new OsvBatchQueryResult(await QueryBatchAsync(purls, ct), Reached: true);
        }

        private List<OsvAdvisory> Answer(string purl)
        {
            // purl shape: pkg:npm/{name}@{version} — the name is everything before the last '@'.
            string rest = purl["pkg:npm/".Length..];
            int at = rest.LastIndexOf('@');
            string name = at > 0 ? rest[..at] : rest;

            return advisories
                .Where(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase))
                .Select(a => a.Advisory)
                .ToList();
        }
    }

    /// <summary>
    /// Reproduces the production outage contract exactly: a full-length list of empty results,
    /// no throw, <c>Reached=false</c>. This is what <c>OsvClient</c> returns on a network failure
    /// or any non-2xx (<c>OsvClient.QueryBatchAsync</c>'s two swallow paths), and what
    /// <c>LocalOsvSource</c> returns when its dump directory is missing.
    /// </summary>
    private sealed class UnreachableOsvSource : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
            Task.FromResult(new List<OsvAdvisory>());

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());

        public Task<OsvBatchQueryResult> TryQueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(new OsvBatchQueryResult(
                purls.Select(_ => new List<OsvAdvisory>()).ToList(), Reached: false));
    }

    /// <summary>Returns fewer result sets than it was handed purls — a broken batch contract.</summary>
    private sealed class ShortResultOsvSource : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
            Task.FromResult(new List<OsvAdvisory>());

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(new List<List<OsvAdvisory>> { new() });
    }

    private sealed class ThrowingOsvSource : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
            throw new HttpRequestException("advisory source unreachable");

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(
            IReadOnlyList<string> purls, CancellationToken ct = default) =>
            throw new HttpRequestException("advisory source unreachable");
    }
}
