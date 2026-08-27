using Dependably.Protocol;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The parsed identity of a purl written by a third party: an SBOM generator, a VEX author or a
/// reachability scanner, none of which spell a purl the way this registry's own writers do.
/// </summary>
/// <param name="Ecosystem">The purl type, lowercased. Never null — the type is what makes it a purl.</param>
/// <param name="Name">The name canonicalized for its ecosystem.</param>
/// <param name="Version">The version with qualifiers stripped, or null for a versionless purl.</param>
/// <param name="Key">The version-less canonical purl: the analysis table's <c>purl_key</c>.</param>
public sealed record SbomPurlIdentity(string Ecosystem, string Name, string? Version, string Key);

/// <summary>
/// The single derivation of the version-less canonical purl that keys
/// <c>project_vuln_analysis.purl_key</c>, and of the versioned coordinate the component fold
/// matches on.
///
/// <para>Version-less is the whole point: a triage decision and a reachability verdict are about
/// a package, not about the exact build that happened to be in the SBOM the day the scan ran, so
/// keying on the version would orphan every statement the moment a dependency was bumped. The
/// reachability scanner fingerprints the same version-less form for the same reason.</para>
///
/// <para>Third-party purls need handling this codebase's own writers never produce:
/// <c>?qualifiers</c> and <c>#subpath</c> (which <see cref="PurlParser.TryParse"/> leaves on the
/// version), a missing version (which makes <c>TryParse</c> refuse outright), and types with no
/// registry mapping at all. All three are parsed here rather than refused — a component whose
/// type this registry does not host is still inventory, and a VEX statement about it is still a
/// statement.</para>
///
/// <para><b>Every writer and every reader of <c>purl_key</c> derives it here.</b> The key is
/// canonicalized — <c>%40</c> decoded, then folded by <see cref="PurlNormalizer.CanonicalName"/>
/// (PEP-503 for PyPI, lowercase for npm/NuGet/RPM/OCI) — so a second, "obvious" derivation that
/// merely cuts the string at an <c>@</c> produces a different key for exactly the spellings that
/// matter: a scoped npm name, a mixed-case NuGet id, an underscored PyPI name. A reader keying
/// rows that way silently finds no VEX statement, and a suppression that was uploaded never
/// applies. That failure is invisible to a test whose fixture happens to use a purl all the
/// spellings agree on, which is why this type is the only place the derivation exists: it lives
/// in Core so the Core-side policy reader and the Management-side ingest writer and exporter all
/// reach the same function rather than each re-deriving one.</para>
/// </summary>
public static class SbomPurlKey
{
    /// <summary>
    /// The derivation itself: the canonical version-less purl for an ecosystem and a raw name.
    /// Idempotent, so it is safe to re-apply to an already-canonicalized name.
    /// </summary>
    public static string KeyOf(string ecosystem, string name)
    {
        string type = ecosystem.ToLowerInvariant();
        // %40 is how a scoped npm name is spelled in a purl; decoding it here is what makes the
        // SBOM's spelling and a scanner's spelling of the same package one key.
        string decoded = name.Replace("%40", "@", StringComparison.Ordinal);
        return PurlNormalizer.NameOnly(type, PurlNormalizer.CanonicalName(type, decoded));
    }

    /// <summary>
    /// The key for a stored <c>sbom_components</c> row. Prefers the parsed columns the ingest
    /// writer filled, and falls back to re-parsing the verbatim purl for a row whose parse
    /// produced no ecosystem/name. Null when the row carries no purl identity at all — such a
    /// component has nothing a VEX statement or a SARIF result could bind to.
    /// </summary>
    public static string? ForComponent(string? ecosystem, string? purlName, string? purl) =>
        !string.IsNullOrWhiteSpace(ecosystem) && !string.IsNullOrWhiteSpace(purlName)
            ? KeyOf(ecosystem, purlName)
            : TryParse(purl)?.Key;

    /// <summary>
    /// Parses a purl into its canonical identity, or returns null when the string is not
    /// purl-shaped. An unmapped purl type passes through lowercased rather than being dropped.
    /// </summary>
    public static SbomPurlIdentity? TryParse(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl))
        {
            return null;
        }

        string trimmed = purl.Trim();
        if (!trimmed.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Qualifiers and subpath are metadata about where a package came from, not part of its
        // identity, and both sort after the version — strip them before anything else reads the
        // string, or two spellings of one package become two rows.
        string body = trimmed;
        int hash = body.IndexOf('#', StringComparison.Ordinal);
        if (hash >= 0)
        {
            body = body[..hash];
        }

        int question = body.IndexOf('?', StringComparison.Ordinal);
        if (question >= 0)
        {
            body = body[..question];
        }

        string rest = body[4..];
        int slash = rest.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0)
        {
            return null;
        }

        string ecosystem = rest[..slash].ToLowerInvariant();
        string remainder = rest[(slash + 1)..];
        if (remainder.Length == 0)
        {
            return null;
        }

        int at = remainder.LastIndexOf('@');
        string rawName = at >= 0 ? remainder[..at] : remainder;
        string? version = at >= 0 && at + 1 < remainder.Length ? remainder[(at + 1)..] : null;
        if (rawName.Length == 0)
        {
            return null;
        }

        string key = KeyOf(ecosystem, rawName);
        // The canonical name is the key with its "pkg:{type}/" prefix removed, so the two can
        // never disagree about how the name was folded.
        string name = key[(ecosystem.Length + 5)..];
        return new SbomPurlIdentity(ecosystem, name, version, key);
    }

    /// <summary>
    /// The match key for binding a per-vulnerability fact to a component row: the version-less
    /// key plus the version, so two versions of one package in one SBOM stay distinct.
    /// </summary>
    public static string VersionedKey(SbomPurlIdentity identity) =>
        identity.Version is null ? identity.Key : $"{identity.Key}@{identity.Version}";

    /// <summary>
    /// The fallback match key for a component with no purl, and for a fact whose producer
    /// carried a name and version but no purl.
    /// </summary>
    public static string NameVersionKey(string name, string? version) =>
        $"{name.ToLowerInvariant()}@{version ?? string.Empty}";
}
