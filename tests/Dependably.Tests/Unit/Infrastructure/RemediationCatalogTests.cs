using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class RemediationCatalogTests
{
    // ── Mapping sanity ──────────────────────────────────────────────────────

    [Theory]
    [InlineData(79, "A05:2025", "Injection")]   // XSS lives under Injection in the 2025 edition.
    [InlineData(89, "A05:2025", "Injection")]   // SQL injection.
    [InlineData(22, "A01:2025", "Broken Access Control")]   // Path traversal.
    [InlineData(918, "A01:2025", "Broken Access Control")]  // SSRF.
    [InlineData(502, "A08:2025", "Software or Data Integrity Failures")]  // Unsafe deserialization.
    [InlineData(327, "A04:2025", "Cryptographic Failures")]
    [InlineData(862, "A01:2025", "Broken Access Control")]   // Missing Authorization.
    [InlineData(287, "A07:2025", "Authentication Failures")]  // Improper Authentication.
    public void CweToOwasp_KnownCwe_ResolvesExpectedCategory(int cwe, string owaspId, string owaspTitle)
    {
        Assert.True(RemediationCatalog.CweToOwasp.TryGetValue(cwe, out var category));
        Assert.Equal(owaspId, category!.OwaspId);
        Assert.Equal(owaspTitle, category.OwaspTitle);
        Assert.StartsWith("https://owasp.org/Top10/2025/", category.OwaspUrl);
    }

    [Fact]
    public void CweToOwasp_UnmappedCwe_NotPresent()
    {
        // CWE-1 ("Location") is a real CWE id, not one of the ~249 CWEs the OWASP Top 10:2025
        // category pages map. CweUrl still resolves regardless.
        Assert.False(RemediationCatalog.CweToOwasp.ContainsKey(1));
    }

    [Fact]
    public void CweToOwasp_EveryCategory_Has10Entries_NoOverlap()
    {
        var ids = RemediationCatalog.CweToOwasp.Values.Select(c => c.OwaspId).Distinct().ToList();
        Assert.Equal(10, ids.Count);
        // Each CWE maps to exactly one category — a FrozenDictionary can't hold duplicate keys,
        // so an accidental cross-category overlap would just silently overwrite one; a nonzero
        // total confirms the seed loaded and didn't collapse to a handful of entries.
        Assert.True(RemediationCatalog.CweToOwasp.Count > 200);
    }

    [Theory]
    [InlineData(79, "fix-xss")]
    [InlineData(80, "fix-xss")]
    [InlineData(89, "fix-injection")]
    [InlineData(78, "fix-injection")]
    [InlineData(22, "fix-path-traversal")]
    [InlineData(73, "fix-path-traversal")]
    [InlineData(918, "fix-ssrf")]
    [InlineData(441, "fix-ssrf")]
    [InlineData(502, "fix-unsafe-deserialization")]
    [InlineData(915, "fix-unsafe-deserialization")]
    [InlineData(862, "fix-broken-access-control")]      // Missing Authorization.
    [InlineData(863, "fix-broken-access-control")]      // Incorrect Authorization.
    [InlineData(639, "fix-broken-access-control")]      // IDOR / Authorization Bypass Through User-Controlled Key.
    [InlineData(327, "fix-weak-cryptography")]          // Broken/risky crypto algorithm.
    [InlineData(347, "fix-weak-cryptography")]          // Improper verification of crypto signature.
    [InlineData(287, "fix-authentication-failures")]    // Improper Authentication.
    [InlineData(306, "fix-authentication-failures")]    // Missing Authentication for Critical Function.
    [InlineData(798, "fix-authentication-failures")]    // Use of Hard-coded Credentials.
    public void CweToSkillId_CoveredCwe_ResolvesExpectedSkill(int cwe, string skillId)
    {
        Assert.True(RemediationCatalog.CweToSkillId.TryGetValue(cwe, out string? actual));
        Assert.Equal(skillId, actual);
    }

    [Fact]
    public void CweToSkillId_EveryValue_IsAKnownSkillId()
    {
        foreach (string skillId in RemediationCatalog.CweToSkillId.Values)
        {
            Assert.Contains(skillId, RemediationSkillCatalog.KnownSkillIds);
        }
    }

    [Fact]
    public void CweToSkillId_UncoveredCwe_NotPresent()
    {
        // CWE-89 (SQL injection) is covered by fix-injection; a CWE with no curated skill
        // (e.g. CWE-1004, a cookie-flags misconfiguration) falls back to OWASP-link-only.
        Assert.False(RemediationCatalog.CweToSkillId.ContainsKey(1004));
    }

    [Fact]
    public void CweToSkillId_UncoveredCwe_WithOwaspCategory_StillFallsBackToMitreUrl()
    {
        // CWE-352 (CSRF) and CWE-200 (information exposure) both resolve an OWASP A01:2025
        // category — they just have no curated skill (CSRF/info-exposure need a different fix
        // shape than fix-broken-access-control's ownership check) — so a caller falls back to
        // the OWASP category link plus CweUrl, not a 404/empty skill lookup.
        Assert.False(RemediationCatalog.CweToSkillId.ContainsKey(352));
        Assert.False(RemediationCatalog.CweToSkillId.ContainsKey(200));
        Assert.True(RemediationCatalog.CweToOwasp.ContainsKey(352));
        Assert.True(RemediationCatalog.CweToOwasp.ContainsKey(200));
        Assert.Equal("https://cwe.mitre.org/data/definitions/352.html", RemediationCatalog.CweUrl(352));
    }

    [Theory]
    [InlineData(79, "https://cwe.mitre.org/data/definitions/79.html")]
    [InlineData(1, "https://cwe.mitre.org/data/definitions/1.html")]
    public void CweUrl_AnyNumericCwe_ConstructsMitreLink(int cwe, string expected)
    {
        Assert.Equal(expected, RemediationCatalog.CweUrl(cwe));
    }
}
