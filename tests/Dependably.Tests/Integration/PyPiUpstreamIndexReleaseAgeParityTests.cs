using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Dependably.Api.PyPiProtocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// The reported failure, end to end: a release younger than the org's cooldown was advertised by
/// <c>/simple/{name}/</c> and then refused by <c>/packages/{file}</c>. pip does not backtrack to an
/// older version on an HTTP error during download, so an index entry it cannot fetch is a hard
/// build failure rather than a resolution it could route around.
///
/// The package is upstream-only here — nothing local, no cached row — which is precisely the case
/// the index could not previously decide, because the PEP 503 HTML it fetched carries no dates.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiUpstreamIndexReleaseAgeParityTests : IAsyncLifetime
{
    private static readonly FakeTimeProvider Clock = TestTime.Frozen();
    private readonly DependablyFactory _factory = new() { FrozenClock = Clock };

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    /// <summary>
    /// Both halves of the invariant in one request pair: the too-young release is absent from the
    /// index, and — proving the index is hiding exactly what the download path refuses rather than
    /// hiding at random — that same file 403s when requested directly. The older release stays
    /// listed and downloadable, which is the version a resolver lands on instead.
    /// </summary>
    [Fact]
    public async Task UpstreamOnlyRelease_YoungerThanTheHold_IsNotAdvertised_AndItsDownloadIs403()
    {
        string name = $"agepar{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string youngFile = $"{name}-3.19.tar.gz";
        string oldFile = $"{name}-3.18.tar.gz";

        var (youngBytes, youngSha) = PyPiFixtures.BuildSdist(name, "3.19");
        var (oldBytes, oldSha) = PyPiFixtures.BuildSdist(name, "3.18");

        string mockBase = _factory.MockUpstream.Urls[0];
        var now = TestTime.KnownNow;

        // The upstream answers PEP 691, so each file carries its own PEP 700 upload-time — the
        // fact the HTML representation cannot express and the release-age arm needs.
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/vnd.pypi.simple.v1+json")
                .WithBody($$"""
                    {"meta":{"api-version":"1.1"},"name":"{{name}}","files":[
                      {"filename":"{{youngFile}}","url":"{{mockBase}}/files/{{youngFile}}",
                       "hashes":{"sha256":"{{youngSha}}"},
                       "upload-time":"{{now.AddHours(-2):o}}","yanked":false},
                      {"filename":"{{oldFile}}","url":"{{mockBase}}/files/{{oldFile}}",
                       "hashes":{"sha256":"{{oldSha}}"},
                       "upload-time":"{{now.AddDays(-60):o}}","yanked":false}
                    ]}
                    """));

        StubFile(youngFile, youngBytes);
        StubFile(oldFile, oldBytes);

        // The download path's own per-version metadata fetch, which is what stamps published_at on
        // the first-fetch record and so drives the 403 half of the assertion.
        StubVersionJson(name, "3.19", youngFile, now.AddHours(-2));
        StubVersionJson(name, "3.18", oldFile, now.AddDays(-60));

        await SetMinReleaseAgeHoursAsync(24);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        var index = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, index.StatusCode);
        string html = await index.Content.ReadAsStringAsync();

        Assert.DoesNotContain(youngFile, html, StringComparison.Ordinal);
        Assert.Contains(oldFile, html, StringComparison.Ordinal);

        // Parity, in the direction that matters: the hidden file is hidden because it is refused.
        var refused = await client.GetAsync($"/packages/{youngFile}");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        // And the advertised one is genuinely servable, so the index is not merely hiding things.
        var served = await client.GetAsync($"/packages/{oldFile}");
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
    }

    /// <summary>
    /// The control: the same upstream document with no cooldown configured advertises both files.
    /// Without it, a renderer that dropped every upstream entry — or one that failed closed on a
    /// document it could not read — would satisfy the test above while breaking every install.
    /// </summary>
    [Fact]
    public async Task UpstreamOnlyRelease_WithNoHoldConfigured_IsAdvertised()
    {
        string name = $"agectl{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string youngFile = $"{name}-3.19.tar.gz";
        var (youngBytes, youngSha) = PyPiFixtures.BuildSdist(name, "3.19");
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/vnd.pypi.simple.v1+json")
                .WithBody($$"""
                    {"meta":{"api-version":"1.1"},"name":"{{name}}","files":[
                      {"filename":"{{youngFile}}","url":"{{mockBase}}/files/{{youngFile}}",
                       "hashes":{"sha256":"{{youngSha}}"},
                       "upload-time":"{{TestTime.KnownNow.AddHours(-2):o}}","yanked":false}
                    ]}
                    """));
        StubFile(youngFile, youngBytes);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string html = await (await client.GetAsync($"/simple/{name}/")).Content.ReadAsStringAsync();
        Assert.Contains(youngFile, html, StringComparison.Ordinal);
    }

    /// <summary>
    /// An upstream that ignores the Accept and answers PEP 503 must still work. HTML carries no
    /// dates, so the hold cannot be decided at index time and fails open — the same posture the
    /// gate takes for an unknown publish timestamp. Failing closed would empty the index for every
    /// HTML-only upstream the moment a tenant configured a cooldown.
    /// </summary>
    [Fact]
    public async Task HtmlOnlyUpstream_StillServesItsIndex_WithTheHoldFailingOpen()
    {
        string name = $"agehtml{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string file = $"{name}-3.19.tar.gz";
        var (sdistBytes, sdistSha) = PyPiFixtures.BuildSdist(name, "3.19");
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody($"""
                    <!DOCTYPE html><html><body>
                    <a href="{mockBase}/files/{file}#sha256={sdistSha}">{file}</a>
                    </body></html>
                    """));
        StubFile(file, sdistBytes);

        await SetMinReleaseAgeHoursAsync(24);

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        string html = await (await client.GetAsync($"/simple/{name}/")).Content.ReadAsStringAsync();
        Assert.Contains(file, html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The index render and the download path both resolve against <c>{base}/simple/{name}/</c>,
    /// and both must send the same Accept so they keep sharing one upstream fetch. Two consumers
    /// sending different Accepts for one URL are two single-flight keys and two cache entries —
    /// invisible on a standard instance, where the upstream body cache is off and both forward
    /// anyway, but a doubling of simple-index traffic in edge mode, where absorbing that load is
    /// the node's whole purpose.
    ///
    /// Asserting the Accept rather than a request count is deliberate: the count is what the
    /// caching layer happens to do, while the header is the property that makes sharing possible
    /// at all, and it stays true on an instance with the body cache disabled.
    /// </summary>
    [Fact]
    public async Task IndexRenderAndDownloadResolution_SendTheSameAcceptForTheSameUrl()
    {
        string name = $"agesame{Guid.NewGuid():N}"[..14].ToLowerInvariant();
        string file = $"{name}-1.0.0.tar.gz";
        var (bytes, sha) = PyPiFixtures.BuildSdist(name, "1.0.0");
        string mockBase = _factory.MockUpstream.Urls[0];

        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/simple/{name}/").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/vnd.pypi.simple.v1+json")
                .WithBody($$"""
                    {"meta":{"api-version":"1.1"},"name":"{{name}}","files":[
                      {"filename":"{{file}}","url":"{{mockBase}}/files/{{file}}",
                       "hashes":{"sha256":"{{sha}}"},
                       "upload-time":"{{TestTime.KnownNow.AddDays(-90):o}}","yanked":false}
                    ]}
                    """));
        StubFile(file, bytes);
        StubVersionJson(name, "1.0.0", file, TestTime.KnownNow.AddDays(-90));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBasic(token);

        // Drive both consumers: the index render, then the download, which resolves the file's
        // upstream URL out of that same document.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/simple/{name}/")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/packages/{file}")).StatusCode);

        var accepts = _factory.MockUpstream.LogEntries
            .Where(e => string.Equals(e.RequestMessage?.Path, $"/simple/{name}/", StringComparison.OrdinalIgnoreCase))
            .Select(e => e.RequestMessage?.Headers is { } h && h.TryGetValue("Accept", out var v)
                ? string.Join(",", v)
                : null)
            .ToList();

        Assert.NotEmpty(accepts);
        Assert.All(accepts, a => Assert.Equal(PyPiSimpleIndexHelper.UpstreamAccept, a));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private void StubFile(string filename, byte[] bytes) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/files/{filename}").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(bytes));

    private void StubVersionJson(string name, string version, string filename, DateTimeOffset uploadTime) =>
        _factory.MockUpstream
            .Given(Request.Create().WithPath($"/pypi/{name}/{version}/json").UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody($$"""
                    {"info":{"name":"{{name}}","version":"{{version}}"},
                     "urls":[{"filename":"{{filename}}","upload_time_iso_8601":"{{uploadTime:o}}"}]}
                    """));

    private async Task SetMinReleaseAgeHoursAsync(int? minReleaseAgeHours)
    {
        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var put = await admin.PutAsJsonAsync("/api/v1/proxy-settings", new
        {
            proxyPassthroughEnabled = true,
            maxOsvScoreTolerance = 10.0,
            minReleaseAgeHours,
        });
        put.EnsureSuccessStatusCode();
    }
}
