using Dependably.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Serves every curated skill embedded in this assembly (see <see cref="SkillCatalog"/>) — the
/// client-config family the Setup page offers as an alternative to copying a configuration by
/// hand, and the remediation family the Vulnerabilities panel links each finding to. Public and
/// unauthenticated on the <c>LicensesController</c> / <c>RemediationController</c> precedent: the
/// content is static, identical for every tenant, and carries zero tenant data, so anonymity is
/// what makes the copy-paste <c>curl … -o ~/.claude/skills/&lt;id&gt;/SKILL.md</c> one-liner work
/// without first minting a token. <c>skillId</c> is validated against the closed embedded-manifest
/// sets only — no user input ever reaches a file/resource path.
/// </summary>
[ApiController]
// authz-ok: static curated skill content embedded in this assembly, identical for every tenant and
// carrying zero tenant data; anonymity is what makes the documented curl one-liner work. skillId is
// validated against the closed embedded manifest, never a path.
[AllowAnonymous]
[EnableRateLimiting("anon")]
public sealed class SkillsController : ControllerBase
{
    /// <summary>GET /api/v1/skills — index of every curated skill (id, name, description, family, and ecosystem/scope for the config family).</summary>
    [HttpGet("api/v1/skills")]
    public IActionResult GetSkillsIndex() => Ok(SkillCatalog.Index);

    /// <summary>
    /// GET /api/v1/skills/bundle — every curated skill as one zip, laid out as
    /// <c>&lt;id&gt;/SKILL.md</c> so it unpacks straight into an assistant's skills directory.
    /// Optionally narrowed to one family (<c>config</c> or <c>remediation</c>).
    /// </summary>
    /// <remarks>
    /// The literal <c>bundle</c> segment outranks the <c>{skillId}</c> parameter in ASP.NET route
    /// precedence, so this route wins regardless of declaration order — and <c>bundle</c> is not a
    /// known skill id, so nothing is shadowed either way. <c>SkillsControllerTests</c> pins both.
    /// </remarks>
    [HttpGet("api/v1/skills/bundle")]
    public IActionResult GetSkillsBundle([FromQuery] string? family = null)
    {
        if (family is not null and not SkillFamilies.Config and not SkillFamilies.Remediation)
        {
            return NotFound();
        }

        byte[] zip = SkillCatalog.BuildBundle(family);
        string name = family is null ? "dependably-skills" : $"dependably-{family}-skills";
        return File(zip, "application/zip", $"{name}.zip");
    }

    /// <summary>GET /api/v1/skills/{skillId} — raw SKILL.md markdown for one curated skill.</summary>
    [HttpGet("api/v1/skills/{skillId}")]
    public IActionResult GetSkill(string skillId)
    {
        string? markdown = SkillCatalog.TryGetSkillMarkdown(skillId);
        return markdown is null ? NotFound() : Content(markdown, "text/markdown; charset=utf-8");
    }
}
