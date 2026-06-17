using System.Net;
using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Dependably.Tests.Integration.OpenApi;

/// <summary>
/// Verifies the two-document OpenAPI split: management endpoints under
/// <c>/api/v1/</c> belong in <c>/openapi/management.json</c>; protocol surfaces
/// at canonical roots (<c>/v2/</c> OCI, <c>/simple/</c> PyPI, etc.) belong in
/// <c>/openapi/protocol.json</c>. The two documents must be path-disjoint —
/// a <c>ShouldInclude</c> regression that let an endpoint leak into both
/// documents would silently break the API surface contract.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OpenApiSplitTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public OpenApiSplitTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task ManagementDocument_OnlyContainsManagementPaths()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var paths = await ReadPathsAsync(resp);
        Assert.NotEmpty(paths);
        // Management paths are /api/v1/… (versioned REST) and /saml/… (SSO browser flows).
        Assert.All(paths, p =>
            Assert.True(
                p.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase)
                || p.StartsWith("/saml/", StringComparison.OrdinalIgnoreCase),
                $"Unexpected path in management document: {p}"));
    }

    [Fact]
    public async Task ProtocolDocument_ExcludesManagementPathsAndIncludesProtocolSurfaces()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var paths = await ReadPathsAsync(resp);
        Assert.NotEmpty(paths);
        Assert.DoesNotContain(paths, p =>
            p.StartsWith("/api/v1/", StringComparison.OrdinalIgnoreCase));
        // SAML SSO flows are management routes, not package-client protocol surfaces.
        Assert.DoesNotContain(paths, p =>
            p.StartsWith("/saml/", StringComparison.OrdinalIgnoreCase));

        // Must include canonical protocol roots — these are the surfaces the split exists to expose.
        Assert.Contains(paths, p => p.StartsWith("/v2", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(paths, p => p.StartsWith("/simple/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ManagementAndProtocol_AreSetDisjoint()
    {
        using var client = _factory.CreateClient();

        var managementResp = await client.GetAsync("/openapi/management.json");
        Assert.Equal(HttpStatusCode.OK, managementResp.StatusCode);
        var managementPaths = await ReadPathsAsync(managementResp);

        var protocolResp = await client.GetAsync("/openapi/protocol.json");
        Assert.Equal(HttpStatusCode.OK, protocolResp.StatusCode);
        var protocolPaths = await ReadPathsAsync(protocolResp);

        string[] overlap = managementPaths
            .Intersect(protocolPaths, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.Empty(overlap);
    }

    /// <summary>
    /// Guards against an AmbiguousMatchException regression: registering both
    /// <c>MapGet("/api/v1/docs")</c> (for the redirect) and <c>MapGet("/api/v1/docs/")</c>
    /// (for the shell) made every doc request 500 because endpoint routing treats the
    /// two templates as equivalent. The fix is a middleware-based redirect; this test
    /// asserts the canonicalisation still works and the bare URL doesn't 500.
    /// </summary>
    [Theory]
    [InlineData("/api/v1/docs", "/api/v1/docs/")]
    [InlineData("/docs", "/docs/")]
    public async Task DocsBareUrl_Redirects_ToTrailingSlash(string from, string to)
    {
        using var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
        var resp = await client.GetAsync(from);
        Assert.Equal(HttpStatusCode.PermanentRedirect, resp.StatusCode);
        Assert.Equal(to, resp.Headers.Location?.OriginalString);
    }

    private static async Task<IReadOnlyList<string>> ReadPathsAsync(HttpResponseMessage resp)
    {
        string body = await resp.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("paths", out var pathsElement)
            || pathsElement.ValueKind != JsonValueKind.Object)
        {
            return Array.Empty<string>();
        }

        var result = new List<string>();
        foreach (var prop in pathsElement.EnumerateObject())
        {
            result.Add(prop.Name);
        }
        return result;
    }
}
