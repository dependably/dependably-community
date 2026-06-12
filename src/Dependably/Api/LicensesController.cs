using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Public, unauthenticated third-party attribution endpoint. Returns the curated
/// notices.json produced by the Docker build (build/extract-notices.mjs running over
/// CycloneDX SBOMs). When the file is absent — typical of a local <c>dotnet run</c> —
/// returns a stub document so the SPA renders a clear dev-mode hint instead of a 404.
/// </summary>
[ApiController]
[AllowAnonymous]
[EnableRateLimiting("anon")]
public sealed class LicensesController : ControllerBase
{
    [HttpGet("api/v1/licenses")]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "notices.json");
        if (!System.IO.File.Exists(path))
        {
            return Ok(new
            {
                generatedAt = (string?)null,
                count = 0,
                components = Array.Empty<object>(),
                devModeStub = true,
            });
        }

        string json = await System.IO.File.ReadAllTextAsync(path, ct);
        return Content(json, "application/json; charset=utf-8");
    }
}
