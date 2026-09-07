using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Serves the curated remediation skills embedded in this assembly (see
/// <see cref="SkillCatalog"/>). Public and unauthenticated — exact
/// <c>LicensesController</c> precedent: the content is static, identical for every tenant, and
/// carries zero tenant data, so anonymity is what makes the copy-paste
/// <c>curl … -o ~/.claude/skills/&lt;id&gt;/SKILL.md</c> one-liner in the Vulnerabilities detail
/// panel work without a token. <c>skillId</c> is validated against the closed embedded-manifest
/// set only — no user input ever reaches a file/resource path.
///
/// These routes stay scoped to the remediation family even though the catalogue behind them now
/// also holds the client-config skills: one-liners already copied out of a running instance keep
/// resolving, and generalising the catalogue must not widen what a shipped route returns. The
/// whole corpus is served by <see cref="SkillsController"/> instead.
/// </summary>
[ApiController]
// authz-ok: static curated remediation content embedded in this assembly, identical for every
// tenant and carrying zero tenant data; anonymity is what makes the documented curl one-liner
// work. skillId is validated against the closed embedded manifest, never a path.
[AllowAnonymous]
[EnableRateLimiting("anon")]
public sealed class RemediationController : ControllerBase
{
    /// <summary>GET /api/v1/remediation/skills — index of every curated remediation skill (id, name, description).</summary>
    [HttpGet("api/v1/remediation/skills")]
    public IActionResult GetSkillsIndex() => Ok(SkillCatalog.RemediationIndex);

    /// <summary>GET /api/v1/remediation/skills/{skillId} — raw SKILL.md markdown for one curated remediation skill.</summary>
    [HttpGet("api/v1/remediation/skills/{skillId}")]
    public IActionResult GetSkill(string skillId)
    {
        string? markdown = SkillCatalog.TryGetRemediationSkillMarkdown(skillId);
        return markdown is null ? NotFound() : Content(markdown, "text/markdown; charset=utf-8");
    }
}
