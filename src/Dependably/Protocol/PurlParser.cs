namespace Dependably.Protocol;

public record ParsedPurl(string Ecosystem, string Name, string Version);

public static class PurlParser
{
    /// <summary>
    /// Parses a PURL string into its components.
    /// Supports pkg:pypi/..., pkg:npm/..., pkg:nuget/...
    /// Returns null if the PURL cannot be parsed.
    /// </summary>
    public static ParsedPurl? TryParse(string purl)
    {
        // Format: pkg:{type}/{name}@{version}
        if (!purl.StartsWith("pkg:"))
            return null;

        var rest = purl[4..]; // strip "pkg:"
        var slashIdx = rest.IndexOf('/');
        if (slashIdx < 0)
            return null;

        var ecosystem = rest[..slashIdx];
        if (string.IsNullOrEmpty(ecosystem))
            return null;

        var remainder = rest[(slashIdx + 1)..];

        var atIdx = remainder.LastIndexOf('@');
        if (atIdx < 0)
            return null;

        var rawName = remainder[..atIdx];
        var version = remainder[(atIdx + 1)..];

        // Decode %40 back to @ for scoped npm packages
        var name = rawName.Replace("%40", "@");

        return new ParsedPurl(ecosystem, name, version);
    }
}
