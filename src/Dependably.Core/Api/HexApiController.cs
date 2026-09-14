using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Hex;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// The Hex API plane at <c>/hex/api/</c>: what <c>mix hex.publish</c>, <c>rebar3 hex publish</c>,
/// <c>mix hex.retire</c> and the docs publisher talk to. Every response is an Erlang term
/// (<c>application/vnd.hex+erlang</c>) when the client asks for one — hex_core has no JSON
/// decoder, so a JSON reply would reach it as an empty body — and JSON otherwise. The read
/// plane a client resolves from is <see cref="HexController"/>.
/// </summary>
[ApiController]
public sealed partial class HexApiController : OrgScopedControllerBase
{
    private const string Ecosystem = "hex";
    private const long RouteHardCeiling = 512L * 1024 * 1024;
    private const long MaxTermBodyBytes = 1024 * 1024;

    private readonly HexControllerServices _svc;
    private readonly HexApiControllerServices _api;

    public HexApiController(HexControllerServices svc, HexApiControllerServices api)
    {
        _svc = svc;
        _api = api;
    }

    // ── Reads ────────────────────────────────────────────────────────────────

    /// <summary>GET /hex/api/users/me — the caller's identity, which <c>mix hex.publish</c> reads before publishing.</summary>
    [HttpGet("/hex/api/users/me")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetMe(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var token = await ResolveHexTokenAsync(orgId, ct);
        if (token is null)
        {
            return Unauthorized();
        }

        if (!token.HasCapability(Capabilities.ReadMetadata))
        {
            AuthDenialRecorder.RecordCapabilityDenied(
                HttpContext, token, required: Capabilities.ReadMetadata, ecosystem: Ecosystem, orgId: orgId);
            return Error(StatusCodes.Status403Forbidden, "read:metadata capability required.");
        }

        string username = token.AuditActorLabel ?? await _api.Identity.DisplayNameForAsync(orgId, token, ct) ?? "token";
        // No organizations: Mix offers to transfer a new package to an organization only when
        // the account belongs to one on hex.pm, and this registry's repository is the org itself.
        return Reply(StatusCodes.Status200OK, new Dictionary<string, object?>
        {
            ["username"] = username,
            ["organizations"] = new List<object?>(),
            ["url"] = $"{BaseUrl()}/hex/api/users/me",
        });
    }

    /// <summary>GET /hex/api/packages/{name} — the package view for a package this org holds.</summary>
    [HttpGet("/hex/api/packages/{name}")]
    [HttpGet("/hex/api/repos/{repo}/packages/{name}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetPackage(string name, string? repo, CancellationToken ct)
    {
        if (!RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name))
        {
            return NotFoundTerm();
        }

        string orgId = CurrentTenantId();
        var gate = await AuthorizeReadAsync(orgId, ct);
        if (gate.Error is not null)
        {
            return gate.Error;
        }

        var held = await _svc.Releases.ListForPackageAsync(orgId, name, ct);
        return held.Count == 0 ? NotFoundTerm() : Reply(StatusCodes.Status200OK, PackageView(name, held));
    }

    /// <summary>GET /hex/api/packages/{name}/releases/{version} — one release this org holds.</summary>
    [HttpGet("/hex/api/packages/{name}/releases/{version}")]
    [HttpGet("/hex/api/repos/{repo}/packages/{name}/releases/{version}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetRelease(string name, string version, string? repo, CancellationToken ct)
    {
        if (!RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name) || !HexNaming.IsValidVersion(version))
        {
            return NotFoundTerm();
        }

        string orgId = CurrentTenantId();
        var gate = await AuthorizeReadAsync(orgId, ct);
        if (gate.Error is not null)
        {
            return gate.Error;
        }

        var release = (await _svc.Releases.ListForPackageAsync(orgId, name, ct)).FirstOrDefault(r => r.Version == version);
        return release is null ? NotFoundTerm() : Reply(StatusCodes.Status200OK, ReleaseView(name, release));
    }

    // ── Publish ──────────────────────────────────────────────────────────────

    /// <summary>
    /// POST /hex/api/packages/{name}/releases?replace= — publishes a package tarball. The
    /// tarball is the request body; its <c>metadata.config</c> must name the same package as the
    /// route and a strict SemVer version, or the publish is refused with 422 before anything is
    /// stored. Requires the <c>publish:hex</c> capability.
    /// </summary>
    [HttpPost("/hex/api/packages/{name}/releases")]
    [HttpPost("/hex/api/repos/{repo}/packages/{name}/releases")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> Publish(string name, string? repo, [FromQuery] bool replace, CancellationToken ct)
    {
        if (_api.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        if (!RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name))
        {
            return NotFoundTerm();
        }

        string orgId = CurrentTenantId();
        var token = await ResolveHexTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"hex\"";
            return Unauthorized();
        }

        if (!token.HasCapability(Capabilities.PublishHex))
        {
            AuthDenialRecorder.RecordCapabilityDenied(
                HttpContext, token, required: Capabilities.PublishHex, ecosystem: Ecosystem, orgId: orgId);
            return Error(StatusCodes.Status403Forbidden, "publish:hex capability required.");
        }

        long uploadCap = (await _api.UploadLimits.ResolveAsync(orgId, Ecosystem, ct)) ?? RouteHardCeiling;
        byte[]? body = await ReadBodyBoundedAsync(uploadCap, ct);
        if (body is null)
        {
            return Error(StatusCodes.Status413PayloadTooLarge, $"Package tarball exceeds the hex upload limit of {uploadCap} bytes.");
        }

        HexTarballParsed tarball;
        HexPackageMetadata meta;
        try
        {
            tarball = HexTarball.Parse(body, uploadCap);
            meta = HexPackageMetadata.Parse(tarball.MetadataText);
        }
        catch (HexProtocolException ex)
        {
            return Error(StatusCodes.Status422UnprocessableEntity, "validation failed", new Dictionary<string, object?> { ["tarball"] = ex.Message });
        }

        return meta.Name != name
            ? Error(StatusCodes.Status422UnprocessableEntity, "validation failed",
                new Dictionary<string, object?> { ["name"] = $"metadata.config names '{meta.Name}' but the publish addressed '{name}'." })
            : await StoreReleaseAsync(orgId, token, meta, tarball, body, uploadCap, replace, ct);
    }

    [SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "The publish facts its caller has already validated: tenant, actor, the parsed metadata and tarball, the raw bytes, and the two admission decisions (size cap, replace).")]
    private async Task<IActionResult> StoreReleaseAsync(
        string orgId, TokenRecord token, HexPackageMetadata meta, HexTarballParsed tarball, byte[] body,
        long uploadCap, bool replace, CancellationToken ct)
    {
        var orgSettings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var claim = await _svc.ClaimResolver.ResolveAsync(orgId, "hex", meta.Name, ct);
        var licenses = meta.Licenses.Where(LicenseExtractor.IsPlausibleSpdx).Distinct(StringComparer.Ordinal).ToList();
        string? repository = meta.Links.Values.FirstOrDefault(v => v.Contains("github.com", StringComparison.OrdinalIgnoreCase) || v.Contains("gitlab", StringComparison.OrdinalIgnoreCase));
        string filename = $"{meta.Name}-{meta.Version}.tar";
        string purl = PurlNormalizer.Hex(meta.Name, meta.Version);

        var request = new PublishRequest
        {
            OrgId = orgId,
            Ecosystem = Ecosystem,
            Name = meta.Name,
            PurlName = meta.Name,
            Version = meta.Version,
            Filename = filename,
            Purl = purl,
            ArtifactBytes = body,
            Origin = "uploaded",
            SizeCap = uploadCap,
            ActorUserId = token.UserId,
            ActorKind = token.ActorKind,
            ActorTokenId = token.Id,
            // `--replace` asks for the overwrite; the org's version-overwrite policy decides.
            AllowOverwrite = replace && (orgSettings?.AllowVersionOverwrite ?? false),
            ClaimState = claim.State,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
            Licenses = licenses.Count > 0 ? licenses : null,
            Homepage = meta.Links.Values.FirstOrDefault(),
            Repository = repository,
            Description = meta.Description,
        };

        var result = await _api.Publish.StoreAndRecordAsync(request, ct);
        if (result is PublishResult.Rejected rej)
        {
            return rej.Code == "version_exists"
                ? Error(StatusCodes.Status422UnprocessableEntity, "validation failed",
                    new Dictionary<string, object?> { ["inserted_at"] = $"{meta.Name} {meta.Version} is already published; publish with --replace if the org allows version overwrite." })
                : Error(rej.HttpStatus, rej.Message);
        }

        string versionId = ((PublishResult.Accepted)result).VersionId;
        await _svc.Releases.UpsertHostedAsync(versionId, new HexReleaseFacts(
            Convert.ToHexString(tarball.InnerChecksum), meta.Requirements,
            meta.App == meta.Name ? null : meta.App, meta.BuildTools, meta.Elixir,
            null, null, false, tarball.MetadataText), ct);
        if (licenses.Count > 0)
        {
            await _api.Licenses.SetLicensesAsync(versionId, licenses, "upstream", ct);
        }

        await _api.Audit.LogActivityAsync(orgId, Ecosystem, purl, "publish", token.AuditActorId,
            actorKind: token.ActorKind, actorLabel: token.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        var stored = await _svc.Releases.GetHostedAsync(orgId, meta.Name, meta.Version, ct);
        var view = stored is null
            ? new Dictionary<string, object?> { ["version"] = meta.Version }
            : ReleaseView(meta.Name, stored);
        Response.Headers.Location = $"{BaseUrl()}/hex/api/packages/{meta.Name}/releases/{meta.Version}";
        return Reply(StatusCodes.Status201Created, view);
    }

    // ── Retire ───────────────────────────────────────────────────────────────

    /// <summary>
    /// POST /hex/api/packages/{name}/releases/{version}/retire — marks a hosted release retired
    /// (Hex's yank: still resolvable when locked, advised against otherwise). The reason is
    /// recorded on the index entry and, as a deprecation, on the version so the deprecated
    /// block arm applies. Requires <c>yank:hex</c>.
    /// </summary>
    [HttpPost("/hex/api/packages/{name}/releases/{version}/retire")]
    [HttpPost("/hex/api/repos/{repo}/packages/{name}/releases/{version}/retire")]
    [EnableRateLimiting("push")]
    public Task<IActionResult> Retire(string name, string version, string? repo, CancellationToken ct)
        => SetRetirementAsync(name, version, repo, retire: true, ct);

    /// <summary>DELETE /hex/api/packages/{name}/releases/{version}/retire — clears a retirement. Requires <c>yank:hex</c>.</summary>
    [HttpDelete("/hex/api/packages/{name}/releases/{version}/retire")]
    [HttpDelete("/hex/api/repos/{repo}/packages/{name}/releases/{version}/retire")]
    [EnableRateLimiting("push")]
    public Task<IActionResult> Unretire(string name, string version, string? repo, CancellationToken ct)
        => SetRetirementAsync(name, version, repo, retire: false, ct);

    // A flat, ordered ladder of refusals whose ORDER is the security property: the edge and
    // naming guards precede the token resolve, the capability check precedes the package lookup
    // so an unauthorized caller cannot distinguish a held release from an absent one, and the
    // body is only read once retirement is known to be the operation. Hoisting any run of it
    // into a helper splits the one sequence a reviewer has to read in order.
    [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "A flat, ordered ladder of authorization and validation refusals; extracting any run of it hides the order that is the point.")]
    private async Task<IActionResult> SetRetirementAsync(string name, string version, string? repo, bool retire, CancellationToken ct)
    {
        if (_api.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        if (!RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name) || !HexNaming.IsValidVersion(version))
        {
            return NotFoundTerm();
        }

        string orgId = CurrentTenantId();
        var token = await ResolveHexTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"hex\"";
            return Unauthorized();
        }

        if (!token.HasCapability(Capabilities.YankHex))
        {
            AuthDenialRecorder.RecordCapabilityDenied(
                HttpContext, token, required: Capabilities.YankHex, ecosystem: Ecosystem, orgId: orgId);
            return Error(StatusCodes.Status403Forbidden, "yank:hex capability required.");
        }

        HexRetirementReason? reason = null;
        string? message = null;
        if (retire)
        {
            var parsed = await ReadRetirementBodyAsync(ct);
            if (parsed.Error is not null)
            {
                return parsed.Error;
            }

            (reason, message) = (parsed.Reason, parsed.Message);
        }

        var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, Ecosystem, name, ct);
        var ver = pkg is null ? null : await _svc.Packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null || ver.Origin == "proxy")
        {
            return NotFoundTerm();
        }

        await _svc.Releases.SetRetirementAsync(orgId, name, version, reason, message, ct);
        await _svc.Packages.UpdateDeprecatedAsync(ver.Id,
            reason is { } r ? HexIndexBuilder.RetirementAsDeprecation(new HexRetirementStatus(r, message)) : null, ct);

        await _api.Audit.LogActivityAsync(orgId, Ecosystem, ver.Purl, retire ? "yank" : "unyank", token.AuditActorId,
            actorKind: token.ActorKind, actorLabel: token.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        if (retire)
        {
            var org = await _svc.Orgs.GetByIdAsync(orgId, ct);
            _api.EventSink.Dispatch(new PackageEventEnvelope(
                EventType: PackageEvents.TypeYank,
                OrgId: orgId,
                OrgSlug: org?.Slug ?? orgId,
                Ecosystem: Ecosystem,
                Name: name,
                Version: version,
                Purl: ver.Purl,
                ArtifactHash: ver.ChecksumSha256 is null ? null : "sha256:" + ver.ChecksumSha256,
                Actor: token.AuditActorId,
                OccurredAt: _svc.Time.GetUtcNow(),
                DataJson: new PackageEvents.Yank(Ecosystem, name, version, ver.Purl, Reason: message).ToJson()));
        }

        return NoContent();
    }

    private readonly record struct RetirementBody(HexRetirementReason? Reason, string? Message, IActionResult? Error);

    private async Task<RetirementBody> ReadRetirementBodyAsync(CancellationToken ct)
    {
        byte[]? body = await ReadBodyBoundedAsync(MaxTermBodyBytes, ct);
        if (body is null)
        {
            return new RetirementBody(null, null, Error(StatusCodes.Status413PayloadTooLarge, "Retirement body too large."));
        }

        string? reasonText;
        string? message;
        try
        {
            (reasonText, message) = IsErlangContentType(Request.ContentType)
                ? ReadRetirementFieldsFromTerm(body)
                : ReadRetirementFieldsFromJson(body);
        }
        catch (Exception ex) when (ex is ErlangTermException or JsonException)
        {
            return new RetirementBody(null, null, Error(StatusCodes.Status400BadRequest, "bad request"));
        }

        var reason = reasonText switch
        {
            "other" => HexRetirementReason.Other,
            "invalid" => HexRetirementReason.Invalid,
            "security" => HexRetirementReason.Security,
            "deprecated" => HexRetirementReason.Deprecated,
            "renamed" => HexRetirementReason.Renamed,
            _ => (HexRetirementReason?)null,
        };
        return reason is null
            ? new RetirementBody(null, null, Error(StatusCodes.Status422UnprocessableEntity, "validation failed",
                new Dictionary<string, object?> { ["reason"] = "must be one of other, invalid, security, deprecated, renamed" }))
            : new RetirementBody(reason, string.IsNullOrWhiteSpace(message) ? null : message.Trim(), null);
    }


    /// <summary>The <c>reason</c>/<c>message</c> fields of an Erlang-term retirement body, or (null, null) when the body is not a map.</summary>
    private static (string? Reason, string? Message) ReadRetirementFieldsFromTerm(byte[] body) =>
        ErlangTermFormat.Decode(body) is IReadOnlyDictionary<object, object?> map
            ? (map.GetValueOrDefault("reason") as string, map.GetValueOrDefault("message") as string)
            : (null, null);

    /// <summary>The <c>reason</c>/<c>message</c> fields of a JSON retirement body, or (null, null) when the body is empty or not an object.</summary>
    private static (string? Reason, string? Message) ReadRetirementFieldsFromJson(byte[] body)
    {
        if (body.Length == 0)
        {
            return (null, null);
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return (null, null);
        }

        return (
            doc.RootElement.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String ? r.GetString() : null,
            doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null);
    }

    // ── Docs ─────────────────────────────────────────────────────────────────

    /// <summary>POST /hex/api/packages/{name}/releases/{version}/docs — stores the release's documentation tarball. Requires <c>publish:hex</c>.</summary>
    [HttpPost("/hex/api/packages/{name}/releases/{version}/docs")]
    [HttpPost("/hex/api/repos/{repo}/packages/{name}/releases/{version}/docs")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> PublishDocs(string name, string version, string? repo, CancellationToken ct)
    {
        if (_api.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var gate = await AuthorizeHostedWriteAsync(name, version, repo, Capabilities.PublishHex, ct);
        if (gate.Error is not null)
        {
            return gate.Error;
        }

        long uploadCap = (await _api.UploadLimits.ResolveAsync(gate.OrgId, Ecosystem, ct)) ?? RouteHardCeiling;
        byte[]? body = await ReadBodyBoundedAsync(uploadCap, ct);
        if (body is null)
        {
            return Error(StatusCodes.Status413PayloadTooLarge, $"Documentation tarball exceeds the hex upload limit of {uploadCap} bytes.");
        }

        if (body.Length < 2 || body[0] != 0x1F || body[1] != 0x8B)
        {
            return Error(StatusCodes.Status422UnprocessableEntity, "validation failed",
                new Dictionary<string, object?> { ["tarball"] = "documentation must be a gzipped tarball" });
        }

        await _svc.Blobs.PutAsync(BlobKeys.HexDocs(gate.OrgId, name, version), new MemoryStream(body), ct);
        await _svc.Releases.SetHasDocsAsync(gate.OrgId, name, version, true, ct);
        Response.Headers.Location = $"{BaseUrl()}/hex/api/packages/{name}/releases/{version}/docs";
        return StatusCode(StatusCodes.Status201Created);
    }

    /// <summary>GET /hex/api/packages/{name}/releases/{version}/docs — redirects to the docs tarball on the read plane.</summary>
    [HttpGet("/hex/api/packages/{name}/releases/{version}/docs")]
    [HttpGet("/hex/api/repos/{repo}/packages/{name}/releases/{version}/docs")]
    [EnableRateLimiting("download")]
    public IActionResult GetDocs(string name, string version, string? repo)
        => !RepoAliasOk(repo) || !HexNaming.IsValidPackageName(name) || !HexNaming.IsValidVersion(version)
            ? NotFoundTerm()
            : Redirect($"{BaseUrl()}/hex/docs/{name}-{version}.tar.gz");

    /// <summary>DELETE /hex/api/packages/{name}/releases/{version}/docs — removes the release's documentation. Requires <c>publish:hex</c>.</summary>
    [HttpDelete("/hex/api/packages/{name}/releases/{version}/docs")]
    [HttpDelete("/hex/api/repos/{repo}/packages/{name}/releases/{version}/docs")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> DeleteDocs(string name, string version, string? repo, CancellationToken ct)
    {
        if (_api.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var gate = await AuthorizeHostedWriteAsync(name, version, repo, Capabilities.PublishHex, ct);
        if (gate.Error is not null)
        {
            return gate.Error;
        }

        await _svc.Blobs.DeleteAsync(BlobKeys.HexDocs(gate.OrgId, name, version), ct);
        await _svc.Releases.SetHasDocsAsync(gate.OrgId, name, version, false, ct);
        return NoContent();
    }

    // ── Revert ───────────────────────────────────────────────────────────────

    /// <summary>
    /// DELETE /hex/api/packages/{name}/releases/{version} — reverts (deletes) a hosted release,
    /// its tarball and its docs. hex.pm bounds this to an hour after publish because its
    /// packages are public; a private registry's own policy governs here, and the action is
    /// audited like every other delete. Requires <c>publish:hex</c>.
    /// </summary>
    [HttpDelete("/hex/api/packages/{name}/releases/{version}")]
    [HttpDelete("/hex/api/repos/{repo}/packages/{name}/releases/{version}")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> Revert(string name, string version, string? repo, CancellationToken ct)
    {
        if (_api.EdgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

        var gate = await AuthorizeHostedWriteAsync(name, version, repo, Capabilities.PublishHex, ct);
        if (gate.Error is not null)
        {
            return gate.Error;
        }

        var ver = gate.Version!;
        await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(ver.BlobKey), ct);
        await _svc.Blobs.DeleteAsync(BlobKeys.HexDocs(gate.OrgId, name, version), ct);
        await _svc.Packages.DeleteVersionAsync(ver.Id, ct);
        await _svc.Packages.DeletePackageIfEmptyAsync(gate.Package!.Id, ct);
        await _api.Audit.LogActivityAsync(gate.OrgId, Ecosystem, ver.Purl, "delete", gate.Token!.AuditActorId,
            actorKind: gate.Token.ActorKind, actorLabel: gate.Token.AuditActorLabel, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);
        return NoContent();
    }

    // ── Everything else the API plane is asked for ───────────────────────────

    /// <summary>Any other API path: a Hex-shaped 404 the client can decode, rather than an HTML page.</summary>
    [HttpGet("/hex/api/{**path}")]
    [HttpPost("/hex/api/{**path}")]
    [HttpPut("/hex/api/{**path}")]
    [HttpDelete("/hex/api/{**path}")]
    [EnableRateLimiting("download")]
    public IActionResult Unsupported(string? path)
    {
        _ = path;
        return NotFoundTerm();
    }
}
