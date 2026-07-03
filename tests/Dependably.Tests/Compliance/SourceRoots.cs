namespace Dependably.Tests.Compliance;

/// <summary>
/// Shared source-tree locator for the <c>Category=Compliance</c> / <c>Category=Schema</c>
/// static-scan gates. The application is split across several source roots
/// (<c>src/Dependably</c>, <c>src/Dependably.Core</c>, <c>src/Dependably.Management</c>,
/// <c>src/Dependably.Edge</c>, …); a gate that scans a single hard-coded root either goes
/// red when files move between roots or — worse — goes green-but-blind, scanning a directory
/// whose files have moved away. Every src-scanning gate therefore iterates <see cref="All"/>.
///
/// <para>
/// The repo root is anchored on <c>Dependably.sln</c> (stable across the assembly split);
/// the source roots are discovered by globbing <c>src/Dependably*</c> directories that contain
/// a <c>.csproj</c>. Globbing (rather than a hard-coded list) is the fail-closed property: a
/// future project added under <c>src/</c> is scanned automatically, so a new source root can
/// never silently escape the gates.
/// </para>
/// </summary>
internal static class SourceRoots
{
    /// <summary>
    /// Walks up from the test bin/ directory to the ancestor that contains
    /// <c>Dependably.sln</c>. The sln file is the one artifact guaranteed to sit at the repo
    /// root regardless of how many <c>src/Dependably*</c> projects exist, so anchoring on it
    /// keeps root resolution independent of any particular source directory's presence.
    /// </summary>
    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Dependably.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException(
            $"Could not locate Dependably.sln (the repo-root anchor) from {AppContext.BaseDirectory}.");
    }

    /// <summary>
    /// Every application source root: each directory matching <c>src/Dependably*</c> under the
    /// repo root that contains a <c>.csproj</c>. Discovered by glob, not a hard-coded list, so
    /// projects added by the assembly split (Core/Management/Edge) are covered automatically.
    /// Ordered for stable diagnostics.
    /// </summary>
    public static IReadOnlyList<string> All()
    {
        string src = Path.Combine(RepoRoot(), "src");
        if (!Directory.Exists(src))
        {
            throw new DirectoryNotFoundException($"Source directory not found at {src}.");
        }

        var roots = Directory
            .EnumerateDirectories(src, "Dependably*", SearchOption.TopDirectoryOnly)
            .Where(d => Directory.EnumerateFiles(d, "*.csproj", SearchOption.TopDirectoryOnly).Any())
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToList();

        return roots.Count > 0
            ? roots
            : throw new DirectoryNotFoundException(
                $"No src/Dependably* project directory found under {src}.");
    }

    /// <summary>
    /// Every <c>*.cs</c> file across all source roots, excluding <c>obj/</c> and <c>bin/</c>
    /// build output. This is the enumeration the majority of the src-scanning gates share;
    /// gates with additional per-test exclusions keep those exclusions inline at the call site.
    /// </summary>
    public static IEnumerable<string> AllCSharpFiles()
    {
        foreach (string root in All())
        {
            foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                    || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
                {
                    continue;
                }

                yield return file;
            }
        }
    }

    /// <summary>
    /// The source root that owns <paramref name="file"/>, used so a gate's relative-path
    /// diagnostics stay rooted at the project directory the offending file lives in.
    /// </summary>
    public static string OwningRoot(string file)
    {
        foreach (string root in All())
        {
            if (file.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                return root;
            }
        }

        return RepoRoot();
    }
}
