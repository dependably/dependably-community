using System.Text;

namespace Dependably.Infrastructure;

/// <summary>
/// Derives the download filename for an uploaded SBOM/VEX/SARIF original.
///
/// <para><c>project_documents</c> stores no filename — the upload is a raw JSON body with query
/// parameters, so there is no client-supplied name to keep, and inventing a column would persist a
/// value that drifts the moment a project is renamed. The name is therefore derived, from facts
/// that are already on the row's own joins, every time it is needed.</para>
///
/// <para>The list surface and the download surface both call this, which is what keeps the name in
/// the documents table identical to the one in the download's <c>Content-Disposition</c>. Two
/// independent formatters would disagree the first time either one changed.</para>
/// </summary>
public static class ProjectDocumentNaming
{
    /// <summary>Substituted when a component sanitizes down to nothing at all.</summary>
    private const string EmptySegmentFallback = "document";

    /// <summary>
    /// <c>{projectName}-{versionLabel}-{docType}.json</c>, with every component reduced to
    /// <c>[A-Za-z0-9._-]</c> so no path separator, quote, control character or non-ASCII byte can
    /// reach a <c>Content-Disposition</c> header or a caller's filesystem. Runs of substituted
    /// characters collapse to a single hyphen, and leading/trailing hyphens and dots are trimmed so
    /// the result is never a dotfile or a relative-path fragment.
    /// </summary>
    public static string FileName(string? projectName, string? versionLabel, string? docType)
    {
        var parts = new List<string>(3);
        foreach (string? raw in new[] { projectName, versionLabel, docType })
        {
            string sanitized = Sanitize(raw);
            if (sanitized.Length > 0)
            {
                parts.Add(sanitized);
            }
        }

        return (parts.Count > 0 ? string.Join('-', parts) : EmptySegmentFallback) + ".json";
    }

    /// <summary>
    /// Reduces one filename component to the safe alphabet. Public because the export surface names
    /// rendered documents from the same project/version facts and must fold them identically.
    /// </summary>
    public static string Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var sb = new StringBuilder(value.Length);
        bool lastWasSeparator = false;
        foreach (char c in value.Trim())
        {
            if (char.IsAsciiLetterOrDigit(c) || c == '.' || c == '_' || c == '-')
            {
                sb.Append(c);
                lastWasSeparator = false;
                continue;
            }

            if (!lastWasSeparator)
            {
                sb.Append('-');
                lastWasSeparator = true;
            }
        }

        return sb.ToString().Trim('-', '.');
    }
}
