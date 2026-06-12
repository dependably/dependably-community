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
}
