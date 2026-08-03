namespace Dependably.Infrastructure;

/// <summary>
/// Well-known NuGet symbol servers. NuGet.org runs one at a stable, documented address, so an
/// operator proxying nuget.org should get working symbols without having to know that address;
/// every other feed has to say where its symbol server is, or get none.
///
/// <para>
/// This is a seed for a stored, editable column — never a resolution-time fallback. An operator
/// who clears <c>upstream_registry.symbol_server_url</c> has switched symbol proxying off for that
/// upstream, and nothing may quietly reinstate it.
/// </para>
/// </summary>
public static class NuGetSymbolServers
{
    /// <summary>NuGet.org's symbol server, the SSQP endpoint Visual Studio ships pointed at.</summary>
    public const string NuGetOrg = "https://symbols.nuget.org/download/symbols";

    // Matched on host alone, so the v3 index path (/v3/index.json vs /v3-flatcontainer/…) does not
    // change the answer. Deliberately narrow: only the canonical nuget.org API hosts. A private
    // feed that happens to mirror nuget.org is NOT nuget.org, and guessing its symbol host would
    // send debug-id lookups — which carry the PDB names of private code — somewhere unintended.
    private static readonly string[] NuGetOrgHosts =
        ["api.nuget.org", "www.nuget.org", "nuget.org"];

    /// <summary>
    /// The symbol server to seed for a newly added upstream, or <see langword="null"/> when the
    /// feed's symbol host is unknown — which leaves symbol proxying off for it (fail-closed).
    /// </summary>
    public static string? DefaultFor(string ecosystem, string url)
    {
        return string.Equals(ecosystem, "nuget", StringComparison.Ordinal)
            && Uri.TryCreate(url, UriKind.Absolute, out var uri)
            && NuGetOrgHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase)
                ? NuGetOrg
                : null;
    }
}
