using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Anti-drift gate for <see cref="OperationTagger"/>. The unit tests feed the tagger string
/// literals, so they pass whether or not those literals are what ASP.NET actually emits in
/// <c>http.route</c> — a map key in URL form (<c>/simple/</c> rather than <c>simple</c>) matches
/// no real request, emits no <c>dependably.operation</c>, and fails nothing. That is how the
/// entire protocol half of the map came to be inert while its unit tests stayed green.
///
/// This gate closes that hole from the other side: it resolves the application's real endpoint
/// table and asserts every key the tagger maps on is a route the app actually serves.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OperationTaggerRouteTableTests(DependablyFactory factory)
    : IClassFixture<DependablyFactory>
{
    private HashSet<string> RealRouteTemplates()
    {
        using var scope = factory.Services.CreateScope();
        var source = scope.ServiceProvider.GetRequiredService<EndpointDataSource>();
        return source.Endpoints
            .OfType<RouteEndpoint>()
            .Select(e => e.RoutePattern.RawText)
            .Where(r => !string.IsNullOrEmpty(r))
            .Select(r => r!)
            .ToHashSet(StringComparer.Ordinal);
    }

    [Fact]
    public void EveryMappedRouteExistsInTheRouteTable()
    {
        var real = RealRouteTemplates();
        var missing = OperationTagger.MappedRoutes.Where(r => !real.Contains(r)).Order(StringComparer.Ordinal).ToList();

        Assert.True(missing.Count == 0,
            "OperationTagger maps route templates the application does not serve, so these arms are " +
            "inert and emit no dependably.operation. Use the template exactly as ASP.NET reports it " +
            "in http.route (no leading slash, no trailing slash, inline constraints verbatim):\n  " +
            string.Join("\n  ", missing));
    }

    [Fact]
    public void RegistrationPrefixMatchesRealRoutes()
    {
        // The registration family resolves by prefix rather than by exact key, so the gate above
        // cannot see it. Assert the prefix still selects real routes — and only NuGet ones.
        var matched = RealRouteTemplates()
            .Where(r => r.StartsWith(OperationTagger.NuGetRegistrationPrefix, StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(matched);
        Assert.All(matched, r => Assert.Equal("index.metadata", OperationTagger.Map(r, "GET")));
    }

    [Fact]
    public void SsqpSymbolRouteIsTaggedFromTheRealTemplate()
    {
        // The regression #482 filed: the route a debugger actually fetches PDBs from carried no
        // operation tag. Asserted against the real template rather than a hand-written literal,
        // because the inline regex constraint's escaping is exactly what a hand-written copy gets
        // wrong.
        string ssqp = Assert.Single(
            RealRouteTemplates(),
            r => r.StartsWith("nuget/symbols/{pdbName}", StringComparison.Ordinal));

        Assert.Equal("package.download", OperationTagger.Map(ssqp, "GET"));
    }
}
