using System.Reflection;

namespace Dependably.Infrastructure;

/// <summary>Index entry for one remediation skill — the shape <c>RemediationController</c> returns from the skills index.</summary>
public sealed record RemediationSkillSummary(string Id, string Name, string Description);

/// <summary>
/// Loads the curated remediation skills embedded into this assembly (<c>skills/remediation/&lt;id&gt;/SKILL.md</c>,
/// wired as <c>EmbeddedResource</c> entries in the Management csproj) so air-gapped installs can
/// serve them from the binary rather than fetching from GitHub. <see cref="KnownSkillIds"/> is the
/// closed set <c>RemediationController</c> validates a route's <c>skillId</c> against — no user
/// input reaches a resource lookup that wasn't already in this list.
/// </summary>
public static class RemediationSkillCatalog
{
    public static readonly IReadOnlyList<string> KnownSkillIds =
    [
        "fix-vulnerable-dependency",
        "fix-injection",
        "fix-xss",
        "fix-path-traversal",
        "fix-unsafe-deserialization",
        "fix-ssrf",
        "fix-broken-access-control",
        "fix-weak-cryptography",
        "fix-authentication-failures",
    ];

    private static readonly Lazy<IReadOnlyList<RemediationSkillSummary>> IndexLazy = new(BuildIndex);

    /// <summary>id, name, description parsed from each skill's frontmatter — served by GET /api/v1/remediation/skills.</summary>
    public static IReadOnlyList<RemediationSkillSummary> Index => IndexLazy.Value;

    /// <summary>Raw SKILL.md markdown for a known skill id, or null when the id isn't one of <see cref="KnownSkillIds"/>.</summary>
    public static string? TryGetSkillMarkdown(string skillId) =>
        KnownSkillIds.Contains(skillId, StringComparer.Ordinal) ? LoadResourceText(skillId) : null;

    private static List<RemediationSkillSummary> BuildIndex()
    {
        var list = new List<RemediationSkillSummary>(KnownSkillIds.Count);
        foreach (string id in KnownSkillIds)
        {
            string? markdown = LoadResourceText(id);
            if (markdown is null)
            {
                continue;
            }

            var (name, description) = ParseFrontmatter(markdown);
            list.Add(new RemediationSkillSummary(id, name ?? id, description ?? string.Empty));
        }

        return list;
    }

    private static string? LoadResourceText(string skillId)
    {
        var assembly = typeof(RemediationSkillCatalog).Assembly;
        string leaf = $"remediation.{skillId}.SKILL.md";
        string? name = assembly.GetManifestResourceNames()
            .SingleOrDefault(n => n.EndsWith(leaf, StringComparison.Ordinal));
        if (name is null)
        {
            return null;
        }

        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// Minimal hand-rolled parser for the two-value YAML frontmatter block every skill starts
    /// with (a <c>---</c>-delimited header with plain-scalar <c>key: value</c> lines, matching
    /// the existing <c>*-configure-*</c> skills). Only <c>name</c> and <c>description</c> are
    /// read; list-valued keys (<c>inputs</c>, <c>cwe</c>) are ignored. A full YAML parser isn't
    /// warranted for two scalar fields.
    /// </summary>
    internal static (string? Name, string? Description) ParseFrontmatter(string markdown)
    {
        string[] lines = markdown.Replace("\r\n", "\n").Split('\n');
        int start = Array.FindIndex(lines, l => l.Trim() == "---");
        if (start < 0)
        {
            return (null, null);
        }

        int end = Array.FindIndex(lines, start + 1, l => l.Trim() == "---");
        if (end < 0)
        {
            return (null, null);
        }

        string? name = null;
        string? description = null;
        for (int i = start + 1; i < end; i++)
        {
            string line = lines[i];
            if (line.Length == 0 || char.IsWhiteSpace(line[0]) || line.TrimStart().StartsWith('-'))
            {
                // Indented / list-item lines belong to a preceding list-valued key — skip.
                continue;
            }

            int colon = line.IndexOf(':');
            if (colon < 0)
            {
                continue;
            }

            string key = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim().Trim('"', '\'');
            if (key == "name")
            {
                name = value;
            }
            else if (key == "description")
            {
                description = value;
            }
        }

        return (name, description);
    }
}
