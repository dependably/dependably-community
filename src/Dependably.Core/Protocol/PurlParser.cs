namespace Dependably.Protocol;

public record ParsedPurl(string Ecosystem, string Name, string Version);

public static class PurlParser
{
    /// <summary>
    /// Parses a PURL string into its components.
    /// Supports pkg:pypi/..., pkg:npm/..., pkg:nuget/..., pkg:golang/...
    /// Returns null if the PURL cannot be parsed.
    /// </summary>
    public static ParsedPurl? TryParse(string purl)
    {
        // Format: pkg:{type}/{name}@{version}
        if (!purl.StartsWith("pkg:"))
        {
            return null;
        }

        string rest = purl[4..]; // strip "pkg:"
        int slashIdx = rest.IndexOf('/');
        if (slashIdx < 0)
        {
            return null;
        }

        string ecosystem = rest[..slashIdx];
        if (string.IsNullOrEmpty(ecosystem))
        {
            return null;
        }

        string remainder = rest[(slashIdx + 1)..];

        int atIdx = remainder.LastIndexOf('@');
        if (atIdx < 0)
        {
            return null;
        }

        string rawName = remainder[..atIdx];
        string version = remainder[(atIdx + 1)..];

        // Decode %40 back to @ for scoped npm packages
        string name = rawName.Replace("%40", "@");

        return new ParsedPurl(ecosystem, name, version);
    }

    /// <summary>
    /// Parses a PURL into the <c>(ecosystem, name, version)</c> coordinate as it is stored on the
    /// proxy cache plane (<c>cache_artifact.name</c> / <c>cache_artifact.version</c>), which is how
    /// version-less quarantine entries (proxy artifacts with no <c>package_versions</c> row) must be
    /// matched. Unlike <see cref="TryParse"/> this strips purl-spec qualifiers (everything from
    /// <c>?</c> onward — e.g. RPM/apk <c>?arch=…</c>) from the version, and maps each ecosystem's
    /// purl name form back to the cache-plane name form: apk drops the <c>alpine/</c> namespace
    /// segment (<c>pkg:apk/alpine/musl@…</c> → <c>musl</c>) and Maven's <c>group/artifact</c> path
    /// separator becomes the <c>group:artifact</c> form the cache plane stores. Returns
    /// <see langword="null"/> when the input is not a versioned PURL.
    /// </summary>
    public static ParsedPurl? TryParseCacheCoordinate(string purl)
    {
        var parsed = TryParse(purl);
        if (parsed is null)
        {
            return null;
        }

        // Qualifiers (?arch=…, ?repository_url=…) are never part of the version the producers
        // store on cache_artifact.version, so drop everything from the first '?'.
        string version = parsed.Version;
        int qmark = version.IndexOf('?');
        if (qmark >= 0)
        {
            version = version[..qmark];
        }

        // Map the purl name segment to the exact form each producer writes to cache_artifact.name.
        string name = parsed.Ecosystem switch
        {
            // PurlNormalizer.Maven emits pkg:maven/{group}/{artifact}@…; MavenCoordinates.PackageName
            // (the value cache_artifact.name is keyed on) is "{group}:{artifact}".
            "maven" => parsed.Name.Replace('/', ':'),
            // PurlNormalizer.Apk emits pkg:apk/alpine/{name}@…; ApkController records the bare name.
            "apk" when parsed.Name.StartsWith("alpine/", StringComparison.OrdinalIgnoreCase)
                => parsed.Name["alpine/".Length..],
            _ => parsed.Name,
        };

        return new ParsedPurl(parsed.Ecosystem, name, version);
    }

    /// <summary>
    /// Extracts just the ecosystem segment from a PURL (<c>pkg:nuget/name@version</c> → <c>nuget</c>),
    /// without requiring a version — unlike <see cref="TryParse"/>, this also accepts versionless
    /// PURLs (<c>pkg:nuget/name</c>). Returns <see langword="null"/> when the input isn't PURL-shaped.
    /// </summary>
    public static string? TryGetEcosystem(string purl)
    {
        const string prefix = "pkg:";
        if (!purl.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }

        int slash = purl.IndexOf('/', prefix.Length);
        if (slash < 0)
        {
            return null;
        }

        string ecosystem = purl[prefix.Length..slash];
        return ecosystem.Length == 0 ? null : ecosystem;
    }
}
