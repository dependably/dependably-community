namespace Dependably.Infrastructure;

/// <summary>
/// The ecosystems whose hosted publishes store several artefacts under ONE
/// <c>package_versions</c> row, with each artefact carried by its own
/// <c>package_version_files</c> row.
///
/// <list type="bullet">
///   <item><b>pypi</b> — a release is a set of distribution files (sdist + wheels, one per
///   platform/ABI), which is the model pypi.org itself exposes.</item>
///   <item><b>nuget</b> — a package and its debug symbols (<c>.nupkg</c> + <c>.snupkg</c>) share a
///   coordinate. <c>dotnet nuget push</c> pushes the adjacent <c>.snupkg</c> automatically, so a
///   one-artefact-per-version model rejects the symbol half of every ordinary push.</item>
/// </list>
///
/// For a covered ecosystem an upload whose filename the version does not yet hold is a NEW file of
/// the release rather than an overwrite, so it bypasses the same-version-push policy (which protects
/// artefact immutability, not release completeness) and the one-artefact-per-version filename guard.
/// Re-uploading a filename the version already holds is a true overwrite and stays policy-gated.
/// </summary>
public static class MultiFileEcosystems
{
    public static readonly IReadOnlySet<string> Covered =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "pypi", "nuget",
        };

    public static bool Covers(string ecosystem) => Covered.Contains(ecosystem);

    /// <summary>
    /// Whether an incoming file should take over the version row's primary-artefact columns
    /// (<c>blob_key</c>, <c>checksum_sha256</c>, …) from the file currently holding them.
    ///
    /// <para>
    /// The version row names ONE artefact, and every reader that resolves a version without a
    /// filename — the flatcontainer serve fallback, the registration index, SBOM export — reads it.
    /// For NuGet that artefact must be the <c>.nupkg</c>: a <c>.snupkg</c> push must never repoint
    /// the row (the package would start serving symbol bytes to package clients), and a
    /// <c>.nupkg</c> arriving at a coordinate whose row still names a <c>.snupkg</c> — the
    /// symbols-first push order — must take it over.
    /// </para>
    ///
    /// <para>
    /// PyPI has no comparable ranking between an sdist and a wheel, so the first file uploaded
    /// stays primary and this never promotes.
    /// </para>
    /// </summary>
    public static bool PromotesToPrimary(string ecosystem, string incomingFilename, string currentPrimaryFilename)
        => ecosystem == "nuget"
            && incomingFilename.EndsWith(NuGetPackageExtension, StringComparison.OrdinalIgnoreCase)
            && currentPrimaryFilename.EndsWith(NuGetSymbolExtension, StringComparison.OrdinalIgnoreCase);

    /// <summary>Extension of a NuGet package artefact — the primary artefact of a NuGet version.</summary>
    public const string NuGetPackageExtension = ".nupkg";

    /// <summary>Extension of a NuGet symbol artefact, which never becomes the primary artefact.</summary>
    public const string NuGetSymbolExtension = ".snupkg";

    /// <summary>
    /// Whether two filenames name the same KIND of artefact, compared by extension.
    ///
    /// <para>
    /// Serve paths that fall back from a requested filename to a version's primary artefact use
    /// this to refuse a substitution across kinds. A symbols-only version's primary IS its
    /// <c>.snupkg</c>, so an unguarded fallback answers a <c>.nupkg</c> request with symbol bytes —
    /// the restore succeeds and nothing above it reports an error. Compared by extension rather
    /// than by exact name because those fallbacks exist precisely to absorb name skew (a stored
    /// mixed-case filename versus the lowercased name NuGet clients request).
    /// </para>
    /// </summary>
    public static bool SameArtifactKind(string filename, string otherFilename) =>
        Path.GetExtension(filename).Equals(
            Path.GetExtension(otherFilename), StringComparison.OrdinalIgnoreCase);
}
