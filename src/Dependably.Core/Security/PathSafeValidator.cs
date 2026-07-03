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

    /// <summary>
    /// Validates a route value that is embedded as a single path segment of an upstream
    /// proxy URL. Applies all the base path-safety rules plus a ban on <c>%</c>: ASP.NET
    /// keeps <c>%2F</c> (and other encoded sequences) undecoded in route values, so an
    /// encoded slash or traversal would survive into the composed upstream request and be
    /// decoded there. No package ecosystem allows <c>%</c> in names, versions, or filenames.
    /// </summary>
    public static ValidationResult ValidateUpstreamSegment(string value, string fieldName)
        => value.Contains('%')
            ? ValidationResult.Fail(fieldName, "must not contain percent-encoded sequences")
            : Validate(value, fieldName);
}

public readonly record struct ValidationResult(bool IsValid, string? FieldName, string? Message)
{
    public static ValidationResult Ok() => new(true, null, null);
    public static ValidationResult Fail(string fieldName, string message) => new(false, fieldName, message);
}
