using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json.Nodes;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Outcome of an install/lifecycle-script scan over one artefact: whether a script that runs
/// automatically on install was found, and a discriminator naming which kind fired
/// (<c>npm:postinstall</c>, <c>pypi:setup.py</c>, <c>nuget:install.ps1</c>, <c>nuget:msbuild</c>).
/// <see cref="Kind"/> is NULL when <see cref="HasScript"/> is false.
/// </summary>
public readonly record struct InstallScriptResult(bool HasScript, string? Kind)
{
    /// <summary>Convenience sentinel for "no script detected" (or an unsupported ecosystem).</summary>
    public static readonly InstallScriptResult None = new(false, null);
}

/// <summary>
/// Maps artefact bytes to an <see cref="InstallScriptResult"/> for the supply-chain
/// install-script block-gate signal. Detection is best-effort and fail-soft: a malformed or
/// unreadable archive returns <see cref="InstallScriptResult.None"/> rather than throwing, so a
/// detection failure never fails an otherwise valid fetch or publish.
///
/// <para>Decompression runs under the same zip/gzip-bomb budgets the validators use
/// (<see cref="TarScanLimits"/>, <see cref="ZipEntryLimits"/>) — no unbounded read is introduced;
/// the per-archive entry-count cap bounds the per-entry name checks for the zip ecosystems.</para>
///
/// <para>Coverage: npm (<c>scripts.preinstall</c>/<c>install</c>/<c>postinstall</c>),
/// PyPI (sdist <c>setup.py</c> ⇒ script, wheel ⇒ none), NuGet
/// (<c>tools/install.ps1</c>/<c>init.ps1</c> or <c>build/*.targets</c>/<c>*.props</c>), and RPM
/// (any non-empty scriptlet phase: <c>%pre</c>, <c>%post</c>, <c>%preun</c>, <c>%postun</c>,
/// <c>%pretrans</c>, <c>%posttrans</c> ⇒ kind <c>rpm:scriptlet</c>).</para>
/// </summary>
public static class ScriptDetectionService
{
    // Maximum zip entries inspected when scanning a NuGet .nupkg. nupkgs are a few hundred
    // entries at most; this caps the per-entry name scan for a crafted package.
    private const int MaxZipEntries = 100_000;

    // npm lifecycle hooks checked in run order; first present hook wins.
    private static readonly string[] NpmInstallHooks = new[] { "preinstall", "install", "postinstall" };

    // Compressed-artefact size we are willing to buffer into memory for detection. npm/PyPI/NuGet
    // packages are small; a blob larger than this (e.g. a multi-GB OCI layer routed here in error)
    // is skipped rather than materialised. Decompression past this stays bounded by the per-archive
    // gzip/zip-bomb guards in TarScanLimits / ArchiveDecompressLimits.
    private const long MaxBufferedArtefactBytes = 512L * 1024 * 1024;

    /// <summary>
    /// Stream overload for the ingest paths: buffers the artefact into a bounded byte[] (skipping
    /// detection and returning <see cref="InstallScriptResult.None"/> when it exceeds
    /// <see cref="MaxBufferedArtefactBytes"/>) and delegates to <see cref="Detect"/>. Fail-soft on
    /// any read error.
    /// </summary>
    public static async Task<InstallScriptResult> DetectAsync(
        string ecosystem, string filename, Stream artefact, CancellationToken ct = default)
    {
        if (ecosystem is not ("npm" or "pypi" or "nuget" or "rpm"))
        {
            return InstallScriptResult.None;
        }

        try
        {
            using var buffer = new MemoryStream();
            using var limited = new LimitedReadStream(artefact, MaxBufferedArtefactBytes, "Artefact");
            await limited.CopyToAsync(buffer, ct);
            return Detect(ecosystem, filename, buffer.ToArray());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return InstallScriptResult.None;
        }
    }

    /// <summary>
    /// Routes by ecosystem and dispatches to the matching detector. Unknown ecosystems and
    /// detector failures return <see cref="InstallScriptResult.None"/>. The buffered bytes are
    /// bounded by the caller (upload size limits + the ingest read cap), never the full stream.
    /// </summary>
    public static InstallScriptResult Detect(string ecosystem, string filename, byte[] bytes)
    {
        try
        {
            return ecosystem switch
            {
                "npm" => DetectNpm(bytes),
                "pypi" => DetectPyPi(filename, bytes),
                "nuget" => DetectNuGet(bytes),
                "rpm" => DetectRpm(bytes),
                _ => InstallScriptResult.None,
            };
        }
        catch
        {
            // Fail-soft: a corrupt or unexpected archive must not break ingest. The artefact
            // still serves; the signal simply stays false until a clean re-fetch/republish.
            return InstallScriptResult.None;
        }
    }

    // npm: open the gzipped tar, read the top-level package.json, and report a script when
    // scripts contains any of preinstall/install/postinstall (the hooks npm runs automatically
    // on `npm install`). Reuses the tarball-reading shape of NpmTarballValidator.
    private static InstallScriptResult DetectNpm(byte[] bytes)
    {
        using var gzip = new LimitedReadStream(
            new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress),
            TarScanLimits.MaxTotalDecompressedBytes, "Tarball");
        using var tar = new TarReader(gzip, leaveOpen: false);

        int entryCount = 0;
        while (tar.GetNextEntry() is { } entry)
        {
            if (++entryCount > TarScanLimits.MaxEntries)
            {
                return InstallScriptResult.None;
            }

            if (!NpmTarballValidator.IsTopLevelPackageJson(entry.Name))
            {
                continue;
            }

            using var entryStream = new LimitedReadStream(
                entry.DataStream!, TarScanLimits.MaxManifestBytes, "package.json");
            var json = JsonNode.Parse(entryStream);
            if (json?["scripts"] is not JsonObject scripts)
            {
                return InstallScriptResult.None;
            }

            // Hook precedence mirrors npm's documented run order; report the first present.
            string? firstHook = NpmInstallHooks.FirstOrDefault(h => scripts[h] is not null);
            return firstHook is not null
                ? new InstallScriptResult(true, $"npm:{firstHook}")
                : InstallScriptResult.None;
        }

        return InstallScriptResult.None;
    }

    // PyPI: a wheel (.whl) is pre-built and runs no install-time code — always false. An sdist
    // (.tar.gz/.tgz/.zip) that carries a top-level setup.py executes arbitrary Python at
    // `pip install` time, so a setup.py present in the archive is the signal.
    private static InstallScriptResult DetectPyPi(string filename, byte[] bytes)
    {
        string lowered = filename.ToLowerInvariant();
        if (lowered.EndsWith(".whl", StringComparison.Ordinal))
        {
            return InstallScriptResult.None;
        }

        // Legacy PEP 314 .zip sdists are zip archives; everything else is gzipped tar.
        if (lowered.EndsWith(".zip", StringComparison.Ordinal))
        {
            return DetectPyPiZipSdist(bytes);
        }

        using var gzip = new LimitedReadStream(
            new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress),
            ArchiveDecompressLimits.MaxDecompressedBytes, "Sdist");
        using var tar = new TarReader(gzip, leaveOpen: false);

        int entryCount = 0;
        while (tar.GetNextEntry() is { } entry)
        {
            if (++entryCount > TarScanLimits.MaxEntries)
            {
                return InstallScriptResult.None;
            }

            if (IsTopLevelSetupPy(entry.Name))
            {
                return new InstallScriptResult(true, "pypi:setup.py");
            }
        }

        return InstallScriptResult.None;
    }

    private static InstallScriptResult DetectPyPiZipSdist(byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        int entryCount = 0;
        foreach (var entry in zip.Entries)
        {
            if (++entryCount > MaxZipEntries)
            {
                return InstallScriptResult.None;
            }

            if (IsTopLevelSetupPy(entry.FullName))
            {
                return new InstallScriptResult(true, "pypi:setup.py");
            }
        }

        return InstallScriptResult.None;
    }

    // setup.py at the archive root or inside exactly one {name}-{version}/ wrapper directory
    // (the PEP 314 sdist layout). Deeper nestings are test fixtures or vendored copies, not the
    // install entry point.
    private static bool IsTopLevelSetupPy(string entryName) =>
        entryName.Equals("setup.py", StringComparison.OrdinalIgnoreCase)
        || (entryName.EndsWith("/setup.py", StringComparison.OrdinalIgnoreCase)
            && entryName.IndexOf('/') == entryName.LastIndexOf('/'));

    // NuGet: the .nupkg is a zip. NuGet's classic package-manager install runs
    // tools/install.ps1 and tools/init.ps1 automatically; build/*.targets and build/*.props are
    // imported into the consumer's MSBuild graph and can execute arbitrary tasks at build time.
    private static InstallScriptResult DetectNuGet(byte[] bytes)
    {
        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        bool hasMsbuild = false;
        int entryCount = 0;
        foreach (var entry in zip.Entries)
        {
            if (++entryCount > MaxZipEntries)
            {
                break;
            }

            string name = entry.FullName.Replace('\\', '/');
            if (IsNuGetInstallScript(name))
            {
                // PowerShell install hooks rank above MSBuild imports: they run unconditionally
                // on package-manager install, whereas MSBuild imports only fire on a build.
                return new InstallScriptResult(true, "nuget:install.ps1");
            }

            if (!hasMsbuild && IsNuGetBuildImport(name))
            {
                hasMsbuild = true;
            }
        }

        return hasMsbuild ? new InstallScriptResult(true, "nuget:msbuild") : InstallScriptResult.None;
    }

    // RPM: parse the binary header and check for any non-empty scriptlet phase
    // (%pre, %post, %preun, %postun, %pretrans, %posttrans). The kind string is always
    // "rpm:scriptlet" regardless of which phases are present — the block-gate arm treats the
    // presence of any scriptlet as the signal, consistent with the other ecosystems returning
    // a single kind discriminator.
    private static InstallScriptResult DetectRpm(byte[] bytes)
    {
        var phases = RpmHeaderParser.DetectScriptlets(bytes);
        return phases.Count > 0
            ? new InstallScriptResult(true, "rpm:scriptlet")
            : InstallScriptResult.None;
    }

    private static bool IsNuGetInstallScript(string name) =>
        name.Equals("tools/install.ps1", StringComparison.OrdinalIgnoreCase)
        || name.Equals("tools/init.ps1", StringComparison.OrdinalIgnoreCase);

    private static bool IsNuGetBuildImport(string name) =>
        (name.StartsWith("build/", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("buildTransitive/", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("buildMultiTargeting/", StringComparison.OrdinalIgnoreCase))
        && (name.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".props", StringComparison.OrdinalIgnoreCase));
}
