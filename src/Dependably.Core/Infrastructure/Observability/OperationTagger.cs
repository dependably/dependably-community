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
/// Routes not in this map produce a server span without
/// <c>dependably.operation</c>; the <c>http.route</c> tag still identifies
/// them.
/// </summary>
public static class OperationTagger
{
    public static string? Map(string? route, string? method)
    {
        return route is null
            ? null
            : (route, method) switch
            {
                // PyPI
                ("/simple/", _) => "index.simple",
                ("/simple/{package}/", _) => "index.simple",
                ("/packages/{file}", _) => "package.download",
                ("/pypi/legacy/", "POST") => "package.publish",

                // npm
                ("/npm/{package}", "GET") => "index.metadata",
                ("/npm/@{scope}/{package}", "GET") => "index.metadata",
                ("/npm/{package}/{version}", "GET") => "index.metadata",
                ("/npm/{package}", "PUT") => "package.publish",
                ("/npm/@{scope}/{package}", "PUT") => "package.publish",
                ("/npm/tarballs/{pkg}/{file}", _) => "package.download",
                ("/npm/tarballs/@{scope}/{pkg}/{file}", _) => "package.download",
                ("/npm/{pkg}/-/{file}", _) => "package.download",
                ("/npm/@{scope}/{pkg}/-/{file}", _) => "package.download",

                // NuGet
                ("/nuget/v3/index.json", _) => "index.simple",
                ("/nuget/index.json", _) => "index.simple",
                ("/nuget/query", _) => "index.search",
                ("/nuget/registration/{id}/", _) => "index.metadata",
                ("/nuget/registration5-semver1/{id}/", _) => "index.metadata",
                ("/nuget/registration5-gz-semver1/{id}/", _) => "index.metadata",
                ("/nuget/registration5-semver2/{id}/", _) => "index.metadata",
                ("/nuget/registration5-gz-semver2/{id}/", _) => "index.metadata",
                ("/nuget/flatcontainer/{id}/index.json", _) => "index.metadata",
                ("/nuget/flatcontainer/{id}/{version}/{file}", _) => "package.download",
                ("/nuget/publish", "PUT") => "package.publish",
                ("/nuget/symbols", "PUT") => "package.publish",
                ("/nuget/publish/{id}/{version}", "DELETE") => "package.unlist",
                ("/nuget/symbols/{id}/{version}/{file}", _) => "package.download",

                // Auth
                ("api/v1/auth/login", "POST") => "auth.sso_signin",
                ("login", "GET") => "auth.sso_signin",

                _ => null
            };
    }
}
