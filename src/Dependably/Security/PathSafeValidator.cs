namespace Dependably.Security;

/// <summary>
/// Validates that any string used in blob key construction is safe — no path traversal,
/// no control characters, reasonable length. Returns a RFC 7807 problem detail on failure.
/// </summary>
public static class PathSafeValidator
{
    private const int MaxLength = 200;

    public static ValidationResult Validate(string value, string fieldName)
    {
        if (string.IsNullOrEmpty(value))
            return ValidationResult.Fail(fieldName, "must not be empty");

        if (value.Length > MaxLength)
            return ValidationResult.Fail(fieldName, $"must not exceed {MaxLength} characters");

        if (value.Contains(".."))
            return ValidationResult.Fail(fieldName, "must not contain '..'");

        if (value.Contains('/') || value.Contains('\\'))
            return ValidationResult.Fail(fieldName, "must not contain path separators");

        if (value.Contains('\0'))
            return ValidationResult.Fail(fieldName, "must not contain null bytes");

        if (value.Any(char.IsControl))
            return ValidationResult.Fail(fieldName, "must not contain control characters");

        return ValidationResult.Ok();
    }
}

public readonly record struct ValidationResult(bool IsValid, string? FieldName, string? Message)
{
    public static ValidationResult Ok() => new(true, null, null);
    public static ValidationResult Fail(string fieldName, string message) => new(false, fieldName, message);
}
