using System.Collections.Frozen;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Maps an ASP.NET Core route template (the value of the <c>http.route</c>
/// activity tag) and HTTP method to the canonical
/// <c>dependably.operation</c> name documented in
/// <c>dependably-enterprise/docs/observability/taxonomy.md#operation-vocabulary</c>.
///
/// Wired in <see cref="Program.ConfigureOpenTelemetry"/> via the
/// <c>AddAspNetCoreInstrumentation</c> <c>EnrichWithHttpResponse</c> hook
/// (response-time, after routing has resolved the matched template). This
/// is what makes TraceQL queries like
/// <c>span.dependably.operation="package.download"</c> work for routes that
/// are otherwise just framework-emitted server spans.
///
/// <para>
/// Keys are the route pattern EXACTLY as ASP.NET emits it in <c>http.route</c>:
/// attribute-routed templates carry <b>no leading slash</b> and no trailing slash, and
/// inline constraints survive verbatim including the route parser's doubled braces (see
/// <see cref="SsqpSymbolRoute"/>). A key written in URL form (<c>/simple/</c>) matches nothing
/// and silently disables its arm without failing anything — which is why the table is data
/// rather than a <c>switch</c>: <c>OperationTaggerRouteTableTests</c> enumerates
/// <see cref="MappedRoutes"/> and asserts every key resolves against the application's real
/// endpoint table.
/// </para>
///
/// Routes not in this map produce a server span without
/// <c>dependably.operation</c>; the <c>http.route</c> tag still identifies
/// them.
/// </summary>
public static class OperationTagger
{
    /// <summary>
    /// The SSQP symbol-server read route (<c>NuGetController.GetSymbolFile</c>) as it appears in
    /// <c>http.route</c>. The 40-hex inline regex constraint disambiguates it from the sibling
    /// whole-<c>.snupkg</c> route, and reaches the tag with the route parser's brace escaping
    /// (<c>{{40}}</c>) intact — this is a literal, not a format string.
    /// </summary>
    internal const string SsqpSymbolRoute =
        "nuget/symbols/{pdbName}/{key:regex(^[0-9a-fA-F]{{40}}$)}/{pdbNameEcho}";

    /// <summary>
    /// Prefix of every NuGet registration read route. The surface spans five client-compatibility
    /// flavours (<c>registration</c>, <c>registration5-semver1/2</c> and their <c>-gz-</c>
    /// variants) times three shapes (bare id, <c>{id}/index.json</c>, and the
    /// <c>{version}.json</c> leaf). All fifteen are metadata reads, so they resolve by prefix
    /// rather than as fifteen near-identical table entries.
    /// </summary>
    internal const string NuGetRegistrationPrefix = "nuget/registration";

    // A null Method means "any method"; a method-specific entry wins over it. npm and NuGet both
    // route publish and metadata read through one template, so both forms are needed.
    private static readonly FrozenDictionary<(string Route, string? Method), string> Operations =
        new Dictionary<(string Route, string? Method), string>
        {
            // PyPI
            [("simple", null)] = "index.simple",
            [("simple/{package}", null)] = "index.simple",
            [("packages/{file}", null)] = "package.download",
            [("pypi/legacy", "POST")] = "package.publish",

            // npm
            [("npm/{package}", "GET")] = "index.metadata",
            [("npm/@{scope}/{package}", "GET")] = "index.metadata",
            [("npm/{package}/{version}", "GET")] = "index.metadata",
            [("npm/{package}", "PUT")] = "package.publish",
            [("npm/@{scope}/{package}", "PUT")] = "package.publish",
            [("npm/tarballs/{pkg}/{file}", null)] = "package.download",
            [("npm/tarballs/@{scope}/{pkg}/{file}", null)] = "package.download",
            [("npm/{pkg}/-/{file}", null)] = "package.download",
            [("npm/@{scope}/{pkg}/-/{file}", null)] = "package.download",

            // NuGet
            [("nuget/v3/index.json", null)] = "index.simple",
            [("nuget/index.json", null)] = "index.simple",
            [("nuget/query", null)] = "index.search",
            [("nuget/flatcontainer/{id}/index.json", null)] = "index.metadata",
            [("nuget/flatcontainer/{id}/{version}/{file}", null)] = "package.download",
            [("nuget/publish", "PUT")] = "package.publish",
            [("nuget/symbols", "PUT")] = "package.publish",
            [("nuget/publish/{id}/{version}", "DELETE")] = "package.unlist",
            [("nuget/symbols/{id}/{version}/{file}", null)] = "package.download",
            // Symbol-server read: the route a debugger actually fetches PDBs from. Shares
            // package.download with the sibling .snupkg route; http.route separates the two.
            [(SsqpSymbolRoute, null)] = "package.download",

            // Auth
            [("api/v1/auth/login", "POST")] = "auth.sso_signin",
        }.ToFrozenDictionary();

    /// <summary>
    /// Every route template this map keys on, for the route-table gate. Excludes the
    /// prefix-resolved registration family, which the gate asserts separately.
    /// </summary>
    internal static IEnumerable<string> MappedRoutes => Operations.Keys.Select(k => k.Route).Distinct();

    public static string? Map(string? route, string? method)
    {
        if (route is null)
        {
            return null;
        }

        // Registration reads resolve by prefix — see NuGetRegistrationPrefix.
        return route.StartsWith(NuGetRegistrationPrefix, StringComparison.Ordinal)
            ? "index.metadata"
            : method is not null && Operations.TryGetValue((route, method), out string? byMethod)
                ? byMethod
                : Operations.TryGetValue((route, null), out string? anyMethod) ? anyMethod : null;
    }
}
