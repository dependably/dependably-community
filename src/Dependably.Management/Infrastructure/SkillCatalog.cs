using System.IO.Compression;
using System.Reflection;

namespace Dependably.Infrastructure;

/// <summary>The two families of curated skill this assembly embeds.</summary>
public static class SkillFamilies
{
    /// <summary>Recipes that point a package-manager client at this registry, one per (ecosystem, scope) Setup cell.</summary>
    public const string Config = "config";

    /// <summary>Recipes for fixing a vulnerability class the scanner surfaced.</summary>
    public const string Remediation = "remediation";
}

/// <summary>
/// Index entry for one curated skill — the shape <c>SkillsController</c> returns from the skills
/// index. <paramref name="Ecosystem"/> and <paramref name="Scope"/> are carried by the config
/// family only; a remediation skill classifies by CWE, not by ecosystem, and leaves both null.
/// </summary>
public sealed record SkillSummary(
    string Id,
    string Name,
    string Description,
    string Family,
    string? Ecosystem,
    string? Scope);

/// <summary>Index entry for one remediation skill — the shape <c>RemediationController</c> has always returned.</summary>
public sealed record RemediationSkillSummary(string Id, string Name, string Description);

/// <summary>
/// Loads the curated skills embedded into this assembly (<c>skills/&lt;id&gt;/SKILL.md</c> for the
/// config family, <c>skills/remediation/&lt;id&gt;/SKILL.md</c> for the remediation one, wired as
/// <c>EmbeddedResource</c> entries in the Management csproj) so air-gapped installs can serve them
/// from the binary rather than fetching from the source repository. The two id lists are the closed
/// sets a route's <c>skillId</c> is validated against — no caller-supplied input reaches a resource
/// lookup that wasn't already in one of them.
/// </summary>
public static class SkillCatalog
{
    /// <summary>
    /// One skill per <c>SetupRecipeCatalog</c> (ecosystem, scope) cell. Five ecosystems are
    /// machine-level only — a repository-rooted file has nowhere to sit for a yum repo, an apk
    /// repositories list, a Terraform CLI config, a Hex client registration, or a Docker login.
    /// <c>SkillCatalogTests</c> asserts this set equals the catalogue's, in both directions.
    /// </summary>
    public static readonly IReadOnlyList<string> ConfigSkillIds =
    [
        "npm-configure-project",
        "npm-configure-global",
        "pypi-configure-project",
        "pypi-configure-global",
        "nuget-configure-project",
        "nuget-configure-global",
        "maven-configure-project",
        "maven-configure-global",
        "go-configure-project",
        "go-configure-global",
        "cargo-configure-project",
        "cargo-configure-global",
        "docker-configure-global",
        "rpm-configure-global",
        "apk-configure-global",
        "terraform-configure-global",
        "hex-configure-global",
    ];

    public static readonly IReadOnlyList<string> RemediationSkillIds =
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

    private static readonly Lazy<IReadOnlyList<SkillSummary>> IndexLazy = new(BuildIndex);

    /// <summary>Every curated skill, config family first — served by GET /api/v1/skills.</summary>
    public static IReadOnlyList<SkillSummary> Index => IndexLazy.Value;

    private static readonly Lazy<IReadOnlyList<RemediationSkillSummary>> RemediationIndexLazy = new(() =>
        Index.Where(s => s.Family == SkillFamilies.Remediation)
             .Select(s => new RemediationSkillSummary(s.Id, s.Name, s.Description))
             .ToList());

    /// <summary>The remediation family alone — served by GET /api/v1/remediation/skills.</summary>
    public static IReadOnlyList<RemediationSkillSummary> RemediationIndex => RemediationIndexLazy.Value;

    /// <summary>Raw SKILL.md markdown for any known skill id, or null when the id isn't a known one.</summary>
    public static string? TryGetSkillMarkdown(string skillId) =>
        RemediationSkillIds.Contains(skillId, StringComparer.Ordinal) ? LoadRemediationResource(skillId)
        : ConfigSkillIds.Contains(skillId, StringComparer.Ordinal) ? LoadConfigResource(skillId)
        : null;

    /// <summary>
    /// Raw markdown for a remediation skill only. <c>RemediationController</c> keeps its original
    /// scope: a config skill reached through the remediation path would widen what a shipped route
    /// returns, which is the one thing generalising the catalogue must not do.
    /// </summary>
    public static string? TryGetRemediationSkillMarkdown(string skillId) =>
        RemediationSkillIds.Contains(skillId, StringComparer.Ordinal) ? LoadRemediationResource(skillId) : null;

    /// <summary>
    /// A zip of every skill in <paramref name="family"/> (or of the whole corpus when it is null),
    /// laid out as <c>&lt;id&gt;/SKILL.md</c> — the same shape the per-skill install one-liner
    /// writes, so unpacking the archive straight into an assistant's skills directory lands every
    /// file where that assistant already looks for it.
    /// </summary>
    /// <remarks>
    /// Entry timestamps are pinned to the zip epoch rather than taken from a clock. The archive is
    /// a pure function of embedded content, and a per-request timestamp would give the same corpus
    /// a different checksum on every download — which is a poor thing to hand an operator of a
    /// registry whose whole subject is verifying that bytes did not change.
    /// </remarks>
    public static byte[] BuildBundle(string? family = null)
    {
        var ids = Index
            .Where(s => family is null || s.Family == family)
            .Select(s => s.Id)
            .ToList();

        using var buffer = new MemoryStream();
        // zip-open-ok: writes an archive, never reads one. The entry-count cap SafeZipArchive
        // enforces exists because ZipArchive.Entries materialises an attacker-controlled central
        // directory on read; nothing is read here, Entries is never touched, and the entry count
        // is the embedded-manifest constant this class already declares.
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (string id in ids)
            {
                string? markdown = TryGetSkillMarkdown(id);
                if (markdown is null)
                {
                    continue;
                }

                var entry = archive.CreateEntry($"{id}/SKILL.md", CompressionLevel.Optimal);
                entry.LastWriteTime = ZipEpoch;
                using var writer = new StreamWriter(entry.Open());
                writer.Write(markdown);
            }
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// 1980-01-01, the earliest instant the zip format can represent. Any fixed value would do;
    /// this one is the conventional choice for a reproducible archive and cannot be mistaken for
    /// a real modification time.
    /// </summary>
    private static readonly DateTimeOffset ZipEpoch = new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static List<SkillSummary> BuildIndex()
    {
        var list = new List<SkillSummary>(ConfigSkillIds.Count + RemediationSkillIds.Count);
        foreach (string id in ConfigSkillIds)
        {
            Add(list, id, SkillFamilies.Config, LoadConfigResource(id));
        }

        foreach (string id in RemediationSkillIds)
        {
            Add(list, id, SkillFamilies.Remediation, LoadRemediationResource(id));
        }

        return list;
    }

    private static void Add(List<SkillSummary> list, string id, string family, string? markdown)
    {
        if (markdown is null)
        {
            return;
        }

        var front = ParseFrontmatter(markdown);
        list.Add(new SkillSummary(
            id,
            front.Name ?? id,
            front.Description ?? string.Empty,
            family,
            family == SkillFamilies.Config ? front.Ecosystem : null,
            family == SkillFamilies.Config ? front.Scope : null));
    }

    private static string? LoadConfigResource(string skillId) => LoadResourceText($"skills.{skillId}.SKILL.md");

    private static string? LoadRemediationResource(string skillId) => LoadResourceText($"remediation.{skillId}.SKILL.md");

    private static string? LoadResourceText(string leaf)
    {
        var assembly = typeof(SkillCatalog).Assembly;
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
    /// Minimal hand-rolled parser for the YAML frontmatter block every skill starts with (a
    /// <c>---</c>-delimited header with plain-scalar <c>key: value</c> lines). Only <c>name</c>,
    /// <c>description</c>, <c>ecosystem</c> and <c>scope</c> are read; list-valued keys
    /// (<c>inputs</c>, <c>cwe</c>) are ignored. A full YAML parser isn't warranted for four scalars.
    /// </summary>
    internal static SkillFrontmatter ParseFrontmatter(string markdown)
    {
        string[] lines = markdown.Replace("\r\n", "\n").Split('\n');
        int start = Array.FindIndex(lines, l => l.Trim() == "---");
        if (start < 0)
        {
            return new SkillFrontmatter(null, null, null, null);
        }

        int end = Array.FindIndex(lines, start + 1, l => l.Trim() == "---");
        if (end < 0)
        {
            return new SkillFrontmatter(null, null, null, null);
        }

        string? name = null;
        string? description = null;
        string? ecosystem = null;
        string? scope = null;
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
            switch (key)
            {
                case "name":
                    name = value;
                    break;
                case "description":
                    description = value;
                    break;
                case "ecosystem":
                    ecosystem = value;
                    break;
                case "scope":
                    scope = value;
                    break;
                default:
                    break;
            }
        }

        return new SkillFrontmatter(name, description, ecosystem, scope);
    }
}

/// <summary>The four scalar frontmatter values <see cref="SkillCatalog.ParseFrontmatter"/> reads.</summary>
internal sealed record SkillFrontmatter(string? Name, string? Description, string? Ecosystem, string? Scope);
