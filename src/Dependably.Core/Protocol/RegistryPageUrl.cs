namespace Dependably.Protocol;

/// <summary>
/// Builds a link to the public registry page where a proxied package version is published —
/// the human-readable page (npmjs.com, pypi.org, nuget.org, Maven Central, crates.io), not the
/// raw artifact-download URL stored in <c>cache_artifact.upstream_url</c>.
/// <para>
/// The page URL is only produced when the artifact's recorded upstream <em>download host</em> is a
/// recognized PUBLIC registry. dependably proxies can point at private registries, and a package
/// cached from a private mirror has no public page to link — reconstructing one from the name
/// would be a lie. In that case (and whenever the coordinate cannot be reconstructed) this returns
/// <see langword="null"/> and the UI hides the link rather than falling back to the download URL.
/// </para>
/// </summary>
public static class RegistryPageUrl
{
    /// <summary>
    /// Reconstructs the public registry page URL for a proxied version, or <see langword="null"/>
    /// when the recorded <paramref name="upstreamUrl"/> host is not a known public registry (e.g. a
    /// private upstream) or the input is otherwise insufficient.
    /// </summary>
    /// <param name="ecosystem">The package ecosystem (<c>npm</c>, <c>pypi</c>, <c>nuget</c>, <c>maven</c>, <c>cargo</c>).</param>
    /// <param name="purl">The version's canonical PURL — used to recover Maven's group/artifact split.</param>
    /// <param name="displayName">The package name as stored/displayed (scope preserved for npm, casing for NuGet).</param>
    /// <param name="version">The version string.</param>
    /// <param name="upstreamUrl">The recorded artifact-download URL; its host gates the reconstruction.</param>
    public static string? ForVersion(string ecosystem, string purl, string displayName, string version, string? upstreamUrl)
    {
        if (string.IsNullOrEmpty(displayName) || string.IsNullOrEmpty(version)
            || string.IsNullOrEmpty(upstreamUrl)
            || !Uri.TryCreate(upstreamUrl, UriKind.Absolute, out var uri))
        {
            return null;
        }

        string host = uri.Host;
        return ecosystem switch
        {
            // registry.npmjs.org/{name}/-/… → the npm package page (scope kept literal, e.g. @babel/core).
            "npm" when HostIs(host, "registry.npmjs.org")
                => $"https://www.npmjs.com/package/{displayName}/v/{version}",
            // files.pythonhosted.org/packages/… → the PyPI project page (PEP 503-normalized name).
            "pypi" when HostIs(host, "files.pythonhosted.org")
                => $"https://pypi.org/project/{PurlNormalizer.PyPiName(displayName)}/{version}/",
            // api.nuget.org/v3-flatcontainer/… → the nuget.org package page (original casing; page is case-insensitive).
            "nuget" when HostIs(host, "api.nuget.org")
                => $"https://www.nuget.org/packages/{displayName}/{version}",
            // static.crates.io/crates/… (the crates.io download host) → the crates.io crate page.
            "cargo" when HostIs(host, "static.crates.io")
                => $"https://crates.io/crates/{displayName}/{version}",
            // repo1.maven.org / repo.maven.apache.org → Maven Central's artifact page.
            "maven" when HostIs(host, "repo1.maven.org") || HostIs(host, "repo.maven.apache.org")
                => MavenCentralUrl(purl, version),
            _ => null,
        };
    }

    private static bool HostIs(string host, string expected)
        => string.Equals(host, expected, StringComparison.OrdinalIgnoreCase);

    // Maven's group/artifact coordinate lives in the PURL (pkg:maven/{group}/{artifact}@{version}),
    // not in a single display name, so recover both from there.
    private static string? MavenCentralUrl(string purl, string version)
    {
        var parsed = PurlParser.TryParse(purl);
        if (parsed is null || parsed.Ecosystem != "maven")
        {
            return null;
        }

        int slash = parsed.Name.LastIndexOf('/');
        if (slash <= 0 || slash == parsed.Name.Length - 1)
        {
            return null;
        }

        string group = parsed.Name[..slash];
        string artifact = parsed.Name[(slash + 1)..];
        return $"https://central.sonatype.com/artifact/{group}/{artifact}/{version}";
    }
}
