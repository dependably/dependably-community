using System.Collections.Frozen;

namespace Dependably.Infrastructure;

/// <summary>
/// A single OWASP Top 10:2025 category — the value side of <see cref="RemediationCatalog.CweToOwasp"/>.
/// </summary>
public sealed record OwaspCategory(string OwaspId, string OwaspTitle, string OwaspUrl);

/// <summary>
/// CWE → OWASP Top 10:2025 category mapping, and CWE → curated remediation skill mapping
/// (<see cref="CweToSkillId"/>). Single source of truth (<c>PurlNormalizer</c>-style): callers
/// look a CWE number up here rather than re-deriving the OWASP category or skill anywhere else.
/// Lives in Management, not Core, so the Edge composition root — which never serves the
/// vulnerability detail endpoint — does not pull this data into its closure.
///
/// <see cref="CweToOwasp"/> is seeded from the official per-category "List of Mapped CWEs" section
/// published in the OWASP Top10 repository, 2025 edition
/// (https://github.com/OWASP/Top10/tree/master/2025/docs/en, mirrored at
/// https://owasp.org/Top10/2025/A0N_2025-*). A CWE id outside this set still resolves a
/// cwe.mitre.org reference via <see cref="CweUrl"/>; it just carries no OWASP category.
/// </summary>
public static class RemediationCatalog
{
    /// <summary>
    /// CWE → curated remediation skill id, for the five class skills served by
    /// <c>RemediationController</c>. The flagship <c>fix-vulnerable-dependency</c> skill applies
    /// to every advisory with a fixed version regardless of CWE, so it is derived separately in
    /// <c>VulnerabilityController</c>, not keyed by CWE here.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Bug", "S3887:Mutable, non-private fields should not be \"readonly\"",
        Justification = "FrozenDictionary is immutable; the analyzer predates System.Collections.Frozen.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S2386:Mutable fields should not be \"public static\"",
        Justification = "FrozenDictionary is immutable; the analyzer predates System.Collections.Frozen.")]
    public static readonly FrozenDictionary<int, string> CweToSkillId = BuildCweToSkillId();

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Bug", "S3887:Mutable, non-private fields should not be \"readonly\"",
        Justification = "FrozenDictionary is immutable; the analyzer predates System.Collections.Frozen.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S2386:Mutable fields should not be \"public static\"",
        Justification = "FrozenDictionary is immutable; the analyzer predates System.Collections.Frozen.")]
    public static readonly FrozenDictionary<int, OwaspCategory> CweToOwasp = BuildCweToOwasp();

    /// <summary>The cwe.mitre.org reference for any numeric CWE id, mapped or not.</summary>
    public static string CweUrl(int cweId) => $"https://cwe.mitre.org/data/definitions/{cweId}.html";

    private static FrozenDictionary<int, string> BuildCweToSkillId()
    {
        var map = new Dictionary<int, string>();

        // fix-xss — Injection (A05:2025) CWEs specific to cross-site scripting.
        AddSkill(map, "fix-xss", 79, 80, 83, 86);

        // fix-injection — the remaining Injection (A05:2025) CWEs: SQL/command/LDAP/XPath/code
        // injection and the shared input-validation/output-encoding root causes.
        AddSkill(map, "fix-injection",
            20, 74, 76, 77, 78, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113,
            114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917);

        // fix-path-traversal — Broken Access Control (A01:2025) traversal/link-following CWEs,
        // plus Insecure Design's CWE-73 (external control of file name or path).
        AddSkill(map, "fix-path-traversal", 22, 23, 36, 59, 61, 65, 73);

        // fix-ssrf — Broken Access Control (A01:2025) CWE-918 (SSRF itself) and CWE-441
        // (confused-deputy proxying), the two CWEs describing server-side request forgery.
        AddSkill(map, "fix-ssrf", 918, 441);

        // fix-unsafe-deserialization — Software or Data Integrity Failures (A08:2025):
        // deserializing untrusted data, and the closely related mass-assignment CWE.
        AddSkill(map, "fix-unsafe-deserialization", 502, 915);

        return map.ToFrozenDictionary();
    }

    private static void AddSkill(Dictionary<int, string> map, string skillId, params ReadOnlySpan<int> cweIds)
    {
        foreach (int cwe in cweIds)
        {
            map[cwe] = skillId;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1075:URIs should not be hardcoded",
        Justification = "Catalog data: the canonical owasp.org Top 10 reference URLs are the payload, not configuration.")]
    private static FrozenDictionary<int, OwaspCategory> BuildCweToOwasp()
    {
        var map = new Dictionary<int, OwaspCategory>();

        AddCategory(map, "A01:2025", "Broken Access Control",
            "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
            22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377,
            379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749,
            862, 863, 918, 922, 1275);

        AddCategory(map, "A02:2025", "Security Misconfiguration",
            "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
            5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174);

        AddCategory(map, "A03:2025", "Software Supply Chain Failures",
            "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            447, 1035, 1104, 1329, 1357, 1395);

        AddCategory(map, "A04:2025", "Cryptographic Failures",
            "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
            261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334,
            335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241);

        AddCategory(map, "A05:2025", "Injection",
            "https://owasp.org/Top10/2025/A05_2025-Injection/",
            20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103,
            104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917);

        AddCategory(map, "A06:2025", "Insecure Design",
            "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
            73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451,
            454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799,
            807, 841, 1021, 1022, 1125);

        AddCategory(map, "A07:2025", "Authentication Failures",
            "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
            258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304,
            305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391,
            1392, 1393);

        AddCategory(map, "A08:2025", "Software or Data Integrity Failures",
            "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
            345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926);

        AddCategory(map, "A09:2025", "Security Logging & Alerting Failures",
            "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
            117, 221, 223, 532, 778);

        AddCategory(map, "A10:2025", "Mishandling of Exceptional Conditions",
            "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
            209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478,
            484, 550, 636, 703, 754, 755, 756);

        return map.ToFrozenDictionary();
    }

    private static void AddCategory(
        Dictionary<int, OwaspCategory> map, string owaspId, string owaspTitle, string owaspUrl,
        params ReadOnlySpan<int> cweIds)
    {
        var category = new OwaspCategory(owaspId, owaspTitle, owaspUrl);
        foreach (int cwe in cweIds)
        {
            map[cwe] = category;
        }
    }
}
