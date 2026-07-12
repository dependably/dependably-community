using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Serves the curated remediation skills embedded in this assembly (see
/// <see cref="RemediationSkillCatalog"/>). Public and unauthenticated — exact
/// <c>LicensesController</c> precedent: the content is static, identical for every tenant, and
/// carries zero tenant data, so anonymity is what makes the copy-paste
/// <c>curl … -o ~/.claude/skills/&lt;id&gt;/SKILL.md</c> one-liner in the Vulnerabilities detail
/// panel work without a token. <c>skillId</c> is validated against the closed embedded-manifest
/// set only — no user input ever reaches a file/resource path.
/// </summary>
[ApiController]
[AllowAnonymous]
[EnableRateLimiting("anon")]
public sealed class RemediationController : ControllerBase
{
    /// <summary>GET /api/v1/remediation/skills — index of every curated skill (id, name, description).</summary>
    [HttpGet("api/v1/remediation/skills")]
    public IActionResult GetSkillsIndex() => Ok(RemediationSkillCatalog.Index);

    /// <summary>GET /api/v1/remediation/skills/{skillId} — raw SKILL.md markdown for one curated skill.</summary>
    [HttpGet("api/v1/remediation/skills/{skillId}")]
    public IActionResult GetSkill(string skillId)
    {
        string? markdown = RemediationSkillCatalog.TryGetSkillMarkdown(skillId);
        return markdown is null ? NotFound() : Content(markdown, "text/markdown; charset=utf-8");
    }
}
