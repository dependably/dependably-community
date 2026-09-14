namespace Dependably.Security;

/// <summary>
/// Single source of truth for deriving a protocol request's ecosystem — using the exact backend
/// id every other subsystem writes (<c>web/src/lib/ecosystems.js</c>'s <c>ECOSYSTEMS</c>,
/// <c>PurlNormalizer</c>, <c>GoController</c>'s own <c>"golang"</c> literal) — from its
/// host-relative request path.
///
/// <para>
/// <see cref="UploadSizeLimitMiddleware"/> and the rate-limit denial audit wiring
/// (<c>RateLimitDenialAuditRecorder</c>) each derived this mapping separately before this type
/// existed, and had already drifted on the <c>/go</c>, <c>/apk</c>, and <c>/terraform</c>
/// prefixes. <c>EcosystemHardcodedListComplianceTests</c> pins every <c>ECOSYSTEMS</c> entry
/// against this table, so an ecosystem lacking (or misspelling) a prefix here fails the build
/// instead of silently writing a wrong or NULL <c>ecosystem</c> column forever.
/// </para>
/// </summary>
internal static class EcosystemPathResolver
{
    // Path prefix -> backend ecosystem id (matches web/src/lib/ecosystems.js's ECOSYSTEMS
    // exactly). OCI's protocol route is /v2/ per the Distribution Spec, and Go's backend id is
    // "golang" even though its protocol route is /go/ — both differ from the route segment only
    // in the on-wire path, never in the id a consumer writes or filters on.
    private static readonly (string Prefix, string Ecosystem)[] PathPrefixes =
    [
        ("/pypi", "pypi"),
        ("/simple", "pypi"),
        ("/packages", "pypi"),
        ("/npm", "npm"),
        ("/nuget", "nuget"),
        ("/maven", "maven"),
        ("/rpm", "rpm"),
        ("/v2", "oci"),
        ("/go", "golang"),
        ("/cargo", "cargo"),
        ("/apk", "apk"),
        ("/terraform", "terraform"),
        ("/hex", "hex"),
    ];

    /// <summary>
    /// Returns the backend ecosystem id for a host-relative request path, or null when the path
    /// matches no known protocol prefix (the management API, the login/invite/anon pre-auth
    /// surfaces, and the embedded SPA all resolve to null).
    ///
    /// <para>
    /// A slash-prefixed <em>route template</em> is equally valid input and is what
    /// <see cref="AuthDenialRecorder"/> passes: only the leading literal segment is read, and a
    /// route's leading segment is a literal on every protocol route (tenancy is host-resolved, so
    /// no ecosystem prefix is ever a route parameter). Feeding it the template rather than the
    /// path is the stricter choice — the template carries no package name.
    /// </para>
    /// </summary>
    public static string? ForPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        foreach (var (prefix, ecosystem) in PathPrefixes)
        {
            if (StartsWithSegment(path, prefix))
            {
                return ecosystem;
            }
        }

        return null;
    }

    // Segment-boundary match so "/nugetfoo" is never mistaken for the "/nuget" ecosystem.
    private static bool StartsWithSegment(string path, string prefix) =>
        path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
        && (path.Length == prefix.Length || path[prefix.Length] == '/');
}
