using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// One parsed OCI repository name + reference. The Distribution Spec requires repo
/// names to match <c>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*</c>;
/// references are either a tag (alphanumeric with limited punctuation) or a digest
/// (<c>{algo}:{hex}</c>).
/// </summary>
public sealed record OciCoordinates(string Repository, string Reference, bool IsDigest)
{
    public string? DigestAlgorithm => IsDigest ? Reference.Split(':', 2)[0] : null;
    public string? DigestHex => IsDigest ? Reference.Split(':', 2)[1] : null;
}

public static partial class OciCoordinatesParser
{
    [GeneratedRegex(@"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")]
    private static partial Regex RepoNameRegex();

    [GeneratedRegex(@"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$")]
    private static partial Regex TagRegex();

    [GeneratedRegex(@"^(sha256|sha512):[a-f0-9]+$")]
    private static partial Regex DigestRegex();

    /// <summary>Validates that <paramref name="name"/> is a legal OCI repo name.</summary>
    public static bool IsValidRepositoryName(string name)
        => !string.IsNullOrWhiteSpace(name) && name.Length <= 255 && RepoNameRegex().IsMatch(name);

    /// <summary>Validates that <paramref name="reference"/> is a legal tag.</summary>
    public static bool IsValidTag(string reference) =>
        !string.IsNullOrWhiteSpace(reference) && TagRegex().IsMatch(reference);

    /// <summary>Validates that <paramref name="reference"/> is a legal digest.</summary>
    public static bool IsValidDigest(string reference) =>
        !string.IsNullOrWhiteSpace(reference) && DigestRegex().IsMatch(reference);

    public static OciCoordinates? Parse(string name, string reference)
    {
        return !IsValidRepositoryName(name) ? null
            : IsValidDigest(reference) ? new OciCoordinates(name, reference, IsDigest: true)
            : IsValidTag(reference) ? new OciCoordinates(name, reference, IsDigest: false)
            : null;
    }
}
