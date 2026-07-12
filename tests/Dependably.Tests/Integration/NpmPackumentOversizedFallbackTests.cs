using System.Net;
using System.Text.Json;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end regression for oversized upstream packuments: when the full packument
/// overflows <see cref="UpstreamClient.MaxMetadataResponseBytes"/>, the packument endpoint
/// must retry with the abbreviated (install-v1) Accept header and serve a merged packument
/// with real per-version dependency metadata — not silently degrade to the local-only
/// fallback, which advertises cached versions with empty dependency lists and breaks
/// downstream installs.
///
/// Fail-before/pass-after: on the old code the oversized full fetch threw
/// <see cref="UpstreamResponseTooLargeException"/>, the handler's catch swallowed it, and —
/// with nothing cached locally — GET /npm/{pkg} returned 404 (or, with cached versions, a
/// dependency-less packument). With the fallback, the abbreviated document is served with
/// its dependencies intact.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NpmPackumentOversizedFallbackTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new();

    public async Task InitializeAsync() => await _factory.InitializeAsync();
    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task OversizedFullPackument_ServesAbbreviatedDocument_WithDependencies()
    {
        string name = $"oversized-{Guid.NewGuid():N}"[..20];

        // Abbreviated-document mapping: matched only when the request negotiates install-v1.
        // Higher priority (lower value) than the catch-all full-document mapping below.
        string corgiJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "8.0.16" },
              "versions": {
                "8.0.16": {
                  "name": "{{name}}",
                  "version": "8.0.16",
                  "dependencies": { "rolldown": "1.0.3", "postcss": "^8.5.15" },
                  "optionalDependencies": { "fsevents": "~2.3.3" },
                  "dist": {
                    "tarball": "https://upstream.example/{{name}}/-/{{name}}-8.0.16.tgz",
                    "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                  }
                }
              }
            }
            """;
        _factory.MockUpstream.Given(
                Request.Create().WithPath($"/{name}")
                    .WithHeader("Accept", $"*{NpmPackumentFetcher.AbbreviatedAccept}*")
                    .UsingGet())
            .AtPriority(1)
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(corgiJson));

        // Full-document mapping (no Accept requirement): a body one byte past the metadata
        // cap, so the capped read throws exactly as it does for vite's real 38 MB packument.
        string oversizedJson = "{\"pad\":\"" + new string('a', (int)UpstreamClient.MaxMetadataResponseBytes) + "\"}";
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .AtPriority(10)
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(oversizedJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        // The abbreviated document's install metadata must survive the merge pipeline —
        // this is exactly what the local-only fallback loses.
        var version = doc.RootElement.GetProperty("versions").GetProperty("8.0.16");
        Assert.Equal("1.0.3", version.GetProperty("dependencies").GetProperty("rolldown").GetString());
        Assert.Equal("~2.3.3", version.GetProperty("optionalDependencies").GetProperty("fsevents").GetString());
        Assert.Equal("8.0.16", doc.RootElement.GetProperty("dist-tags").GetProperty("latest").GetString());

        // Tarball URLs must be rewritten to this registry, same as the full-document path.
        string? tarball = version.GetProperty("dist").GetProperty("tarball").GetString();
        Assert.NotNull(tarball);
        Assert.Contains("/npm/tarballs/", tarball);
    }

    [Fact]
    public async Task UnderCapFullPackument_IsServedWithoutAbbreviatedRetry()
    {
        string name = $"regular-{Guid.NewGuid():N}"[..20];

        // Only a full-document mapping exists; an unexpected abbreviated retry would 404 and
        // surface as a missing packument, failing the assertions below.
        string fullJson = $$"""
            {
              "name": "{{name}}",
              "dist-tags": { "latest": "1.0.0" },
              "time": { "1.0.0": "2020-01-01T00:00:00.000Z" },
              "versions": {
                "1.0.0": {
                  "name": "{{name}}",
                  "version": "1.0.0",
                  "dependencies": { "left-pad": "^1.3.0" },
                  "dist": { "tarball": "https://upstream.example/{{name}}/-/{{name}}-1.0.0.tgz" }
                }
              }
            }
            """;
        _factory.MockUpstream.Given(Request.Create().WithPath($"/{name}").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json").WithBody(fullJson));

        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);

        var resp = await client.GetAsync($"/npm/{name}");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        string json = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);
        var version = doc.RootElement.GetProperty("versions").GetProperty("1.0.0");
        Assert.Equal("^1.3.0", version.GetProperty("dependencies").GetProperty("left-pad").GetString());
        // The full document's time map survives — proof the abbreviated variant wasn't used.
        Assert.True(doc.RootElement.TryGetProperty("time", out _), "full-document time map must be preserved");
    }
}
