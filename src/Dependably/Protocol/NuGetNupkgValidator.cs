using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using NuGet.Versioning;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Validates a <c>.nupkg</c> by reading its <c>.nuspec</c> XML and extracting <c>id</c> and
/// <c>version</c>. Used by the publish controller and the bulk-import controller.
/// Mirrors the rules in <c>NuGetController.ParseNupkg</c>: known nuspec namespace, id charset,
/// version parseable by NuGet.Versioning, mandatory description and authors fields.
/// </summary>
public static partial class NuGetNupkgValidator
{
    private static readonly HashSet<string> KnownNuspecNamespaces = [
        "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd",
        "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"
    ];

    [GeneratedRegex(@"^[A-Za-z0-9_\-\.]+$")]
    private static partial Regex IdRegex();

    /// <summary>
    /// Parses the .nupkg/.snupkg bytes. Returns id+version on success, or a structured
    /// failure that callers can surface.
    /// </summary>
    public static (ValidationResult Result, string? Id, string? Version) Parse(byte[] bytes, bool isSymbol)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);

            if (isSymbol)
            {
                var hasPdb = zip.Entries.Any(e => e.Name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase));
                if (!hasPdb)
                    return (ValidationResult.Fail("content", ".snupkg must contain at least one .pdb file"), null, null);
            }

            var nuspecEntry = zip.Entries.FirstOrDefault(e =>
                e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains('/'));

            if (nuspecEntry is null)
                return (ValidationResult.Fail("content", "No .nuspec found at ZIP root"), null, null);

            using var nuspecStream = nuspecEntry.Open();
            var doc = XDocument.Load(nuspecStream);
            var ns = doc.Root?.Name.NamespaceName ?? "";

            if (!KnownNuspecNamespaces.Contains(ns))
                return (ValidationResult.Fail("content", $"Unknown nuspec namespace: {ns}"), null, null);

            XNamespace xns = ns;
            var metadata = doc.Root?.Element(xns + "metadata");
            var id = metadata?.Element(xns + "id")?.Value?.Trim();
            var version = metadata?.Element(xns + "version")?.Value?.Trim();
            var description = metadata?.Element(xns + "description")?.Value?.Trim();
            var authors = metadata?.Element(xns + "authors")?.Value?.Trim();

            if (string.IsNullOrEmpty(id) || id.Length > 100)
                return (ValidationResult.Fail("id", "id must be 1-100 characters"), null, null);

            if (!IdRegex().IsMatch(id))
                return (ValidationResult.Fail("id", "id contains invalid characters"), null, null);

            if (!NuGetVersion.TryParse(version, out _))
                return (ValidationResult.Fail("version", $"Invalid NuGet version: {version}"), null, null);

            if (string.IsNullOrEmpty(description))
                return (ValidationResult.Fail("description", "description is required"), null, null);

            if (string.IsNullOrEmpty(authors))
                return (ValidationResult.Fail("authors", "authors is required"), null, null);

            return (ValidationResult.Ok(), id, version);
        }
        catch (Exception ex)
        {
            return (ValidationResult.Fail("content", $"Invalid .nupkg: {ex.Message}"), null, null);
        }
    }
}
