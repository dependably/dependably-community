using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Extension methods on WireMockServer to simulate upstream registries
/// (PyPI, npm, NuGet) for proxy and cache-miss tests.
/// </summary>
public static class UpstreamMock
{
    // ── PyPI ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Stubs a PyPI simple index response for a package.
    /// </summary>
    public static WireMockServer StubPyPiSimpleIndex(
        this WireMockServer mock, string name, string version, byte[] wheelBytes)
    {
        var normalized = name.ToLowerInvariant().Replace('_', '-').Replace('.', '-');
        var filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";
        var hash = Convert.ToHexString(SHA256.HashData(wheelBytes)).ToLowerInvariant();

        var html = $"""
            <!DOCTYPE html><html><body>
            <a href="/packages/{filename}#sha256={hash}" data-requires-python="">{filename}</a>
            </body></html>
            """;

        mock.Given(Request.Create()
                .WithPath($"/simple/{normalized}/")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(html));

        mock.Given(Request.Create()
                .WithPath($"/packages/{filename}")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/zip")
                .WithBody(wheelBytes));

        return mock;
    }

    /// <summary>
    /// Stubs a PyPI simple index that returns a tampered checksum (for rejection tests).
    /// </summary>
    public static WireMockServer StubPyPiSimpleIndexTamperedHash(
        this WireMockServer mock, string name, string version, byte[] wheelBytes)
    {
        var normalized = name.ToLowerInvariant().Replace('_', '-').Replace('.', '-');
        var filename = $"{name.Replace('-', '_')}-{version}-py3-none-any.whl";
        const string badHash = "0000000000000000000000000000000000000000000000000000000000000000";

        var html = $"""
            <!DOCTYPE html><html><body>
            <a href="/packages/{filename}#sha256={badHash}">{filename}</a>
            </body></html>
            """;

        mock.Given(Request.Create()
                .WithPath($"/simple/{normalized}/")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "text/html")
                .WithBody(html));

        mock.Given(Request.Create()
                .WithPath($"/packages/{filename}")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithBody(wheelBytes));

        return mock;
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Stubs an npm CouchDB metadata response for a package.
    /// </summary>
    public static WireMockServer StubNpmMetadata(
        this WireMockServer mock, string name, string version, byte[] tarballBytes, string baseUrl)
    {
        var filename = $"{name}-{version}.tgz";
        var sri = $"sha512-{Convert.ToBase64String(SHA512.HashData(tarballBytes))}";

        var json = $$"""
            {
              "name": "{{name}}",
              "versions": {
                "{{version}}": {
                  "name": "{{name}}",
                  "version": "{{version}}",
                  "dist": {
                    "tarball": "{{baseUrl}}/{{name}}/-/{{filename}}",
                    "integrity": "{{sri}}"
                  }
                }
              },
              "dist-tags": { "latest": "{{version}}" }
            }
            """;

        mock.Given(Request.Create()
                .WithPath($"/{name}")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(json));

        mock.Given(Request.Create()
                .WithPath($"/{name}/-/{filename}")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(tarballBytes));

        return mock;
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Stubs a NuGet v3 service index response.
    /// </summary>
    public static WireMockServer StubNuGetServiceIndex(this WireMockServer mock)
    {
        var baseUrl = mock.Urls[0];
        var json = $$"""
            {
              "version": "3.0.0",
              "resources": [
                { "@id": "{{baseUrl}}/registration/", "@type": "RegistrationsBaseUrl/3.6.0" },
                { "@id": "{{baseUrl}}/flatcontainer/", "@type": "PackageBaseAddress/3.0.0" },
                { "@id": "{{baseUrl}}/query", "@type": "SearchQueryService" }
              ]
            }
            """;

        mock.Given(Request.Create()
                .WithPath("/index.json")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(json));

        return mock;
    }

    /// <summary>
    /// Stubs NuGet registration and flatcontainer responses for a package.
    /// </summary>
    public static WireMockServer StubNuGetPackage(
        this WireMockServer mock, string id, string version, byte[] nupkgBytes)
    {
        var baseUrl = mock.Urls[0];
        var lowerId = id.ToLowerInvariant();
        var lowerVersion = version.ToLowerInvariant();

        var registration = $$"""
            {
              "count": 1,
              "items": [{
                "count": 1,
                "items": [{
                  "@id": "{{baseUrl}}/registration/{{lowerId}}/{{lowerVersion}}.json",
                  "catalogEntry": {
                    "id": "{{id}}",
                    "version": "{{version}}",
                    "description": "Test package"
                  },
                  "packageContent": "{{baseUrl}}/flatcontainer/{{lowerId}}/{{lowerVersion}}/{{lowerId}}.{{lowerVersion}}.nupkg"
                }]
              }]
            }
            """;

        mock.Given(Request.Create()
                .WithPath($"/registration/{lowerId}/index.json")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/json")
                .WithBody(registration));

        mock.Given(Request.Create()
                .WithPath($"/flatcontainer/{lowerId}/{lowerVersion}/{lowerId}.{lowerVersion}.nupkg")
                .UsingGet())
            .RespondWith(Response.Create()
                .WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(nupkgBytes));

        return mock;
    }

    /// <summary>
    /// Stubs a 404 from upstream (package not found).
    /// </summary>
    public static WireMockServer StubUpstream404(this WireMockServer mock, string path)
    {
        mock.Given(Request.Create().WithPath(path).UsingAnyMethod())
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.NotFound));
        return mock;
    }
}
