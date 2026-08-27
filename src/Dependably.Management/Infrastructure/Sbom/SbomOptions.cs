namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Instance-level limits for document upload. One byte cap governs all three document kinds:
/// they are produced by the same pipeline about the same build, and a per-kind cap would be
/// three knobs answering one question.
/// </summary>
public sealed record SbomOptions(long MaxUploadBytes)
{
    /// <summary>50 MB — well above any real CycloneDX or SARIF document, well below a DoS.</summary>
    public const long DefaultMaxUploadBytes = 52_428_800;

    /// <summary>
    /// Reads <c>Sbom:MaxUploadBytes</c>, falling back to the default when it is unset, or set to
    /// a value that does not parse or is not positive — an unusable value must not silently
    /// disable the cap.
    /// </summary>
    public static SbomOptions Resolve(IConfiguration configuration)
    {
        string? configured = configuration["Sbom:MaxUploadBytes"];
        return long.TryParse(configured, out long parsed) && parsed > 0
            ? new SbomOptions(parsed)
            : new SbomOptions(DefaultMaxUploadBytes);
    }
}
