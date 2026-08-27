namespace Dependably.Security;

/// <summary>
/// Validates that any string used in blob key construction is safe — no path traversal,
/// no control characters, reasonable length. Returns a RFC 7807 problem detail on failure.
/// </summary>
public static class PathSafeValidator
{
    private const int MaxLength = 200;

    // Ordered safety rules — first violation wins, so the message matches the most
    // specific failure (empty before length, etc.). A flat table keeps each check
    // independent and the method's cognitive complexity low.
    private static readonly (Func<string, bool> Violates, string Message)[] Rules =
    [
        (static v => string.IsNullOrEmpty(v), "must not be empty"),
        (static v => v.Length > MaxLength, $"must not exceed {MaxLength} characters"),
        (static v => v.Contains(".."), "must not contain '..'"),
        (static v => v.Contains('/') || v.Contains('\\'), "must not contain path separators"),
        (static v => v.Contains('\0'), "must not contain null bytes"),
        (static v => v.Any(char.IsControl), "must not contain control characters"),
    ];

    public static ValidationResult Validate(string value, string fieldName)
    {
        foreach (var (violates, message) in Rules)
        {
            if (violates(value))
            {
                return ValidationResult.Fail(fieldName, message);
            }
        }
        return ValidationResult.Ok();
    }

    // Characters that change the STRUCTURE of the composed upstream URL rather than riding
    // inside the segment. Ordered so an existing input keeps the message it already got.
    private static readonly (Func<string, bool> Violates, string Message)[] UpstreamRules =
    [
        (static v => v.Contains('%'), "must not contain percent-encoded sequences"),
        (static v => v.Contains('?') || v.Contains('#'), "must not contain URL delimiters"),
    ];

    /// <summary>
    /// Validates a route value that is embedded as a single path segment of an upstream
    /// proxy URL. Applies all the base path-safety rules plus two bans of its own.
    ///
    /// <para><c>%</c>: ASP.NET keeps <c>%2F</c> (and other encoded sequences) undecoded in route
    /// values, so an encoded slash or traversal would survive into the composed upstream request
    /// and be decoded there.</para>
    ///
    /// <para><c>?</c> and <c>#</c>: both terminate the path when the composed string is parsed as
    /// a URI, so a segment carrying one silently TRUNCATES the request. <c>pkg?a</c> spliced into
    /// <c>{upstream}/registration5-semver1/{id}/{version}.json</c> fetches
    /// <c>/registration5-semver1/pkg</c> with the rest demoted to a query string, and <c>pkg#f</c>
    /// fetches the same path with the rest dropped as a fragment — a different upstream resource
    /// than the caller's coordinate names. The base rules already stop this from leaving the
    /// configured host (no <c>/</c>, no <c>..</c>), so the reachable set is bounded to prefixes of
    /// the intended path, but requesting a resource the coordinate does not name is wrong on its
    /// own terms and the recorded row would carry an id no ecosystem accepts.</para>
    ///
    /// <para>Other URL-reserved characters (<c>&amp;</c>, <c>;</c>, <c>:</c>, <c>@</c>, space) are
    /// deliberately NOT banned: <see cref="Uri"/> percent-encodes them into the same single
    /// segment, so they cannot restructure the request, and banning them would reject legitimate
    /// content in ecosystems that allow them.</para>
    ///
    /// <para>No package ecosystem allows <c>%</c>, <c>?</c> or <c>#</c> in names, versions, or
    /// filenames, so none of this narrows what a real client can ask for.</para>
    /// </summary>
    public static ValidationResult ValidateUpstreamSegment(string value, string fieldName)
    {
        foreach (var (violates, message) in UpstreamRules)
        {
            if (violates(value))
            {
                return ValidationResult.Fail(fieldName, message);
            }
        }

        return Validate(value, fieldName);
    }
}

public readonly record struct ValidationResult(bool IsValid, string? FieldName, string? Message)
{
    public static ValidationResult Ok() => new(true, null, null);
    public static ValidationResult Fail(string fieldName, string message) => new(false, fieldName, message);
}
