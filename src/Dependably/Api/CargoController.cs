using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Cargo sparse registry surface. Implements the Rust sparse registry protocol at
/// <c>/cargo/</c>:
/// <list type="bullet">
///   <item><c>GET /cargo/config.json</c> — registry configuration document</item>
///   <item><c>GET /cargo/api/v1/crates</c> — crates.io-compatible search</item>
///   <item><c>GET /cargo/api/v1/crates/{name}/owners</c> — crate owners (org membership)</item>
///   <item><c>PUT|DELETE /cargo/api/v1/crates/{name}/owners</c> — owner mutation (501)</item>
///   <item><c>PUT /cargo/api/v1/crates/new</c> — crate publish</item>
///   <item><c>DELETE /cargo/api/v1/crates/{name}/{version}/yank</c> — yank a version</item>
///   <item><c>PUT /cargo/api/v1/crates/{name}/{version}/unyank</c> — unyank a version</item>
///   <item><c>GET /cargo/{**path}</c> — sparse index file or crate download dispatch</item>
/// </list>
/// The sparse index path layout follows the Cargo specification:
/// 1-char names live at <c>1/{name}</c>, 2-char at <c>2/{name}</c>,
/// 3-char at <c>3/{c}/{name}</c>, and 4+-char at <c>{ab}/{cd}/{name}</c>
/// where <c>ab</c> and <c>cd</c> are the first and second pairs of the name.
/// </summary>
[ApiController]
public sealed class CargoController : OrgScopedControllerBase
{
    private readonly OrgRepository _orgs;
    private readonly PackageRepository _packages;
    private readonly TokenRepository _tokens;
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly UpstreamRegistryResolver _registries;
    private readonly CargoMetadataRepository _cargoMeta;
    private readonly IPublicUrlBuilder _urls;
    private readonly UpstreamClient _upstream;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly IPackagePublishService _publish;
    private readonly IUploadLimitResolver _uploadLimits;
    private readonly ClaimResolver _claimResolver;
    private readonly ReservedNamespaceService _reserved;
    private readonly AuditRepository _audit;
    private readonly ILogger<CargoController> _logger;

    // Route-level ceiling used when no org/instance Cargo upload limit is configured, so the
    // declared crate length is always bounded before any bytes are buffered. crates.io caps
    // published crates at 10 MiB; a generous self-hosted default is higher but still finite.
    private const long RouteHardCeiling = 256L * 1024 * 1024;

    // Cargo sparse index path segment widths per the registry spec: 1-char and 2-char names
    // have their own top-level directories; 3-char names bucket by the first char; 4+-char
    // names bucket by the first two chars, then the next two chars.
    private const int IndexPath1CharLen = 1;
    private const int IndexPath2CharLen = 2;
    private const int IndexPath3CharLen = 3;
    private const int IndexPathPrefixStride = 2;
    private const int IndexPathSecondPrefixEnd = 4;

    // SHA-256 hex digest prefix length used for ETags (16 hex chars = 64 bits of entropy).
    private const int ETagHexPrefixLength = 16;

    // Crate name and SHA-256 digest length constraints per the Cargo and crates.io spec.
    private const int MaxCrateNameLength = 64;
    private const int Sha256HexLength = 64;

    // Search result page size: maximum packages returned per crates.io-compatible search page.
    private const int MaxSearchPageSize = 100;

    // Owner mutation is not supported; 501 Not Implemented per RFC 9110.
    private const int StatusNotImplemented = 501;

    // Dependency-injection constructor; the parameter list is the controller's declared
    // dependency set and grouping it into an aggregate would hide dependencies without
    // adding cohesion.
#pragma warning disable S107
    public CargoController(
        OrgRepository orgs,
        PackageRepository packages,
        TokenRepository tokens,
        IMetadataStore db,
        IBlobStore blobs,
        UpstreamRegistryResolver registries,
        CargoMetadataRepository cargoMeta,
        IPublicUrlBuilder urls,
        UpstreamClient upstream,
        CacheAccessRecorder cacheRecorder,
        IPackagePublishService publish,
        IUploadLimitResolver uploadLimits,
        ClaimResolver claimResolver,
        ReservedNamespaceService reserved,
        AuditRepository audit,
        ILogger<CargoController> logger)
#pragma warning restore S107
    {
        _orgs = orgs;
        _packages = packages;
        _tokens = tokens;
        _db = db;
        _blobs = blobs;
        _registries = registries;
        _cargoMeta = cargoMeta;
        _urls = urls;
        _upstream = upstream;
        _cacheRecorder = cacheRecorder;
        _publish = publish;
        _uploadLimits = uploadLimits;
        _claimResolver = claimResolver;
        _reserved = reserved;
        _audit = audit;
        _logger = logger;
    }

    // ── Sparse index path computation ────────────────────────────────────────

    /// <summary>
    /// Returns the index sub-path for a crate name per the Cargo sparse registry spec.
    /// The result is the relative path under the registry root (no leading slash).
    /// </summary>
    internal static string IndexPath(string name)
    {
        return name.Length switch
        {
            IndexPath1CharLen => $"1/{name}",
            IndexPath2CharLen => $"2/{name}",
            IndexPath3CharLen => $"3/{name[0]}/{name}",
            _ => $"{name[..IndexPathPrefixStride]}/{name[IndexPathPrefixStride..IndexPathSecondPrefixEnd]}/{name}",
        };
    }

    // ── config.json ──────────────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/config.json — Cargo registry configuration document.
    /// The <c>dl</c> field is the download URL template; Cargo appends
    /// <c>{crate}/{version}/download</c> to form the full download URL.
    /// The <c>api</c> field points to the registry API base for publish/yank.
    /// </summary>
    [HttpGet("/cargo/config.json")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetConfig(CancellationToken ct)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        string baseUrl = _urls.BaseUrl(HttpContext);
        var config = new
        {
            dl = $"{baseUrl}/cargo/api/v1/crates",
            api = $"{baseUrl}/cargo",
        };

        return new JsonResult(config);
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/api/v1/crates?q=&amp;per_page= — crates.io-compatible search over all crates in the org.
    /// Returns the crates.io search envelope: <c>{ crates: [{name, max_version, description}], meta: {total} }</c>.
    /// Both hosted (org-published) and proxy-cached crates in the tenant are searched; results are
    /// filtered to the requesting org by <c>org_id</c>.
    /// Auth follows the same anonymous-pull gate as the rest of the Cargo surface.
    /// </summary>
    [HttpGet("/cargo/api/v1/crates")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> Search(
        [FromQuery] string? q,
        [FromQuery(Name = "per_page")] int perPage = 10,
        CancellationToken ct = default)
    {
        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        // Clamp per_page to 1..100; default matches crates.io's default of 10.
        perPage = Math.Clamp(perPage, 1, MaxSearchPageSize);

        var query = new PackageListQuery(
            OrgId: orgId,
            Limit: perPage,
            Offset: 0,
            Ecosystem: "cargo",
            Search: string.IsNullOrWhiteSpace(q) ? null : q.Trim(),
            SortBy: "name",
            SortDir: "asc");

        var (packages, total) = await _packages.ListPaginatedAsync(query, ct);

        // Build the crates.io search response shape. The cargo client expects snake_case
        // field names (max_version, not maxVersion) — explicit keys guarantee the shape
        // regardless of any global serializer policy.
        var cratesArr = new System.Text.Json.Nodes.JsonArray();
        foreach (var pkg in packages)
        {
            // Resolve the latest non-yanked version so the search result shows the current
            // installable version. Falls back to any version when all are yanked.
            string? maxVersion = await ResolveMaxVersionAsync(pkg.Id, ct);
            cratesArr.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["name"] = pkg.Name,
                ["max_version"] = maxVersion ?? "",
                ["description"] = (System.Text.Json.Nodes.JsonNode?)null,
            });
        }

        return new JsonResult(new System.Text.Json.Nodes.JsonObject
        {
            ["crates"] = cratesArr,
            ["meta"] = new System.Text.Json.Nodes.JsonObject
            {
                ["total"] = total,
            },
        });
    }

    /// <summary>
    /// Resolves the latest non-yanked version for a crate (most recently created among
    /// non-yanked versions). Falls back to the most recently created version when all
    /// versions are yanked. Returns null when the crate has no versions at all.
    /// </summary>
    private async Task<string?> ResolveMaxVersionAsync(string packageId, CancellationToken ct)
    {
        var versions = await _packages.GetVersionsAsync(packageId, ct);
        var nonYanked = versions.Where(v => !v.Yanked).ToList();
        var candidates = nonYanked.Count > 0 ? nonYanked : versions.ToList();
        if (candidates.Count == 0)
        {
            return null;
        }

        // Sort by creation time descending; Cargo semver ordering is not enforced here
        // because self-hosted versions may not follow semver strictly.
        return candidates.OrderByDescending(v => v.CreatedAt).First().Version;
    }

    // ── Owners ────────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/api/v1/crates/{name}/owners — lists crate owners. Returns the org's
    /// membership as a crates.io-compatible owners list: each member maps to a user entry
    /// with their email as the login. Auth requires a valid token (owners are not public).
    /// </summary>
    [HttpGet("/cargo/api/v1/crates/{name}/owners")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetOwners(string name, CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        if (!IsValidCrateName(name) || !PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }

        // Confirm the crate exists in this org before revealing membership.
        var pkg = await _packages.GetByPurlNameAsync(orgId, "cargo", name, ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var members = await _orgs.ListOrgMembersAsync(orgId, ct);

        // crates.io owners shape: { users: [{ id, login, kind }] }. Explicit keys for
        // the snake_case protocol wire format.
        var usersArr = new System.Text.Json.Nodes.JsonArray();
        foreach (var member in members)
        {
            usersArr.Add(new System.Text.Json.Nodes.JsonObject
            {
                ["id"] = member.UserId,
                ["login"] = member.Email,
                ["kind"] = "user",
            });
        }

        return new JsonResult(new System.Text.Json.Nodes.JsonObject
        {
            ["users"] = usersArr,
        });
    }

    /// <summary>
    /// PUT /cargo/api/v1/crates/{name}/owners — add an owner. Owner mutation is not supported
    /// in this registry; access is governed by org membership managed through the registry's
    /// user management API. Returns 501 with an explicit message.
    /// </summary>
    [HttpPut("/cargo/api/v1/crates/{name}/owners")]
    [EnableRateLimiting("push")]
    public IActionResult AddOwners(string name)
        => OwnerMutationNotSupported();

    /// <summary>
    /// DELETE /cargo/api/v1/crates/{name}/owners — remove an owner. Owner mutation is not
    /// supported in this registry; access is governed by org membership managed through the
    /// registry's user management API. Returns 501 with an explicit message.
    /// </summary>
    [HttpDelete("/cargo/api/v1/crates/{name}/owners")]
    [EnableRateLimiting("push")]
    public IActionResult RemoveOwners(string name)
        => OwnerMutationNotSupported();

    private static ObjectResult OwnerMutationNotSupported()
        => new(new ProblemDetails
        {
            Detail = "Owner mutation is not supported by this registry. " +
                     "Access to crates is governed by org membership; " +
                     "manage members through the registry's user management API.",
            Status = StatusNotImplemented,
        })
        { StatusCode = StatusNotImplemented };

    // ── Publish ────────────────────────────────────────────────────────────────

    /// <summary>
    /// PUT /cargo/api/v1/crates/new — Cargo crate publish. The body is a binary frame:
    /// a little-endian u32 JSON-metadata length, the JSON metadata, a little-endian u32
    /// .crate length, then the .crate bytes. Requires a token with the publish:cargo
    /// capability. On success returns the Cargo warnings envelope; the published version
    /// appears in the sparse index immediately and is downloadable by exact coordinate.
    /// </summary>
    [HttpPut("/cargo/api/v1/crates/new")]
    [EnableRateLimiting("push")]
    public async Task<IActionResult> Publish(CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }
        if (!token.HasCapability(Capabilities.PublishCargo))
        {
            return Forbidden("publish:cargo capability required.");
        }

        // Resolve the effective Cargo upload cap before buffering the crate bytes: org
        // ecosystem cap → org global cap → instance cap (layered inside the resolver), with a
        // finite route ceiling when nothing is configured. The declared crate length in the
        // frame header is checked against this cap before the crate is sliced out of the body.
        long uploadCap = (await _uploadLimits.ResolveAsync(orgId, "cargo", ct)) ?? RouteHardCeiling;

        // Read the whole frame bounded by the cap (metadata is small; crate is the bulk).
        // A frame larger than the cap can never hold a valid crate within the cap, so a
        // bounded read is the cheap first gate.
        byte[]? body = await ReadBodyBoundedAsync(uploadCap, ct);
        if (body is null)
        {
            return Payload413($"Publish frame exceeds the cargo upload limit of {uploadCap} bytes.");
        }

        var (frameError, header) = CargoPublishFrame.ReadHeader(body);
        if (frameError != CargoPublishFrame.FrameError.None || header is null)
        {
            return BadRequest(new ProblemDetails
            {
                Detail = $"Malformed Cargo publish frame ({frameError}).",
                Status = StatusCodes.Status400BadRequest,
            });
        }

        // Declared crate length vs the upload cap — reject before slicing the crate bytes.
        if (header.CrateLength > uploadCap)
        {
            return Payload413(
                $"Declared crate size ({header.CrateLength} bytes) exceeds the cargo upload limit of {uploadCap} bytes.");
        }

        var metadata = header.Metadata;
        string name = metadata.Name;
        string version = metadata.Vers;

        // Cargo crate names: lowercase comparison, ASCII alphanumeric plus '-' and '_', max
        // 64 chars (crates.io's limit). PathSafeValidator rejects traversal/control chars; the
        // charset check enforces the Cargo-specific naming rule on top.
        if (!IsValidCrateName(name) || !PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }
        if (string.IsNullOrWhiteSpace(version)
            || !PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate version.", Status = StatusCodes.Status400BadRequest });
        }

        byte[] crateBytes = CargoPublishFrame.SliceCrate(body, header);
        string cksum = ComputeSha256Hex(crateBytes);
        string filename = $"{name}-{version}.crate";

        // Shared publish tail: claim gate, size cap, dedup, quota, blob store, version row,
        // OSV scan, typed audit event. Returns the JSON success envelope on acceptance.
        return await ExecuteCargoPublishAsync(
            new CargoPublishArgs(orgId, name, version, filename, cksum, metadata, crateBytes, uploadCap, token), ct);
    }

    // Cohesive set of resolved values passed to the publish tail, bundled to keep the method
    // signature within the parameter-count threshold (S107).
    private sealed record CargoPublishArgs(
        string OrgId, string Name, string Version, string Filename, string Cksum,
        CargoPublishMetadata Metadata, byte[] CrateBytes, long UploadCap, TokenRecord Token);

    // Builds the publish request, calls the shared publish pipeline, persists the sparse-index
    // line, emits the activity record, and returns the Cargo warnings envelope on success.
    private async Task<IActionResult> ExecuteCargoPublishAsync(
        CargoPublishArgs args, CancellationToken ct)
    {
        var orgSettings = await _orgs.GetSettingsAsync(args.OrgId, ct);
        var claim = await _claimResolver.ResolveAsync(args.OrgId, "cargo", args.Name, ct);
        var request = new PublishRequest
        {
            OrgId = args.OrgId,
            Ecosystem = "cargo",
            Name = args.Name,
            PurlName = args.Name,
            Version = args.Version,
            Filename = args.Filename,
            Purl = PurlNormalizer.Cargo(args.Name, args.Version),
            ArtifactBytes = args.CrateBytes,
            Origin = "uploaded",
            SizeCap = args.UploadCap,
            ActorUserId = args.Token.UserId,
            ActorKind = args.Token.ActorKind,
            AllowOverwrite = orgSettings?.AllowVersionOverwrite ?? false,
            ClaimState = claim.State,
            SourceIp = HttpContext.GetNormalizedRemoteIp(),
        };

        var result = await _publish.StoreAndRecordAsync(request, ct);
        if (result is PublishResult.Rejected rej)
        {
            return rej.Code switch
            {
                "version_exists" => Conflict(new ProblemDetails
                {
                    Detail = $"Crate {args.Name}@{args.Version} already exists. Yank it or bump the version.",
                    Status = StatusCodes.Status409Conflict,
                }),
                _ => StatusCode(rej.HttpStatus, new ProblemDetails { Detail = rej.Message, Status = rej.HttpStatus }),
            };
        }

        string versionId = ((PublishResult.Accepted)result).VersionId;

        // Persist the sparse-index line so the crate is resolvable immediately.
        string indexLine = args.Metadata.ToIndexLine(args.Cksum, yanked: false);
        await _cargoMeta.UpsertIndexLineAsync(versionId, indexLine, ct);

        // Per-version operator action → activity (the publish auditor already emitted the
        // tenant-level package.publish event; activity is the per-version operator record).
        await _audit.LogActivityAsync(args.OrgId, "cargo", request.Purl, "publish", args.Token.UserId,
            actorKind: args.Token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        // Cargo expects a warnings envelope on a successful publish.
        return new JsonResult(new
        {
            warnings = new
            {
                invalid_categories = Array.Empty<string>(),
                invalid_badges = Array.Empty<string>(),
                other = Array.Empty<string>(),
            },
        });
    }

    // ── Yank / unyank ───────────────────────────────────────────────────────────

    /// <summary>
    /// DELETE /cargo/api/v1/crates/{name}/{version}/yank — marks a version yanked. A yanked
    /// version is hidden from dependency resolution but remains downloadable by exact
    /// coordinate. Requires a token with the yank:cargo capability. Returns {"ok":true}.
    /// </summary>
    [HttpDelete("/cargo/api/v1/crates/{name}/{version}/yank")]
    [EnableRateLimiting("push")]
    public Task<IActionResult> Yank(string name, string version, CancellationToken ct)
        => SetYankAsync(name, version, yanked: true, ct);

    /// <summary>
    /// PUT /cargo/api/v1/crates/{name}/{version}/unyank — clears a version's yanked flag.
    /// Requires a token with the yank:cargo capability. Returns {"ok":true}.
    /// </summary>
    [HttpPut("/cargo/api/v1/crates/{name}/{version}/unyank")]
    [EnableRateLimiting("push")]
    public Task<IActionResult> Unyank(string name, string version, CancellationToken ct)
        => SetYankAsync(name, version, yanked: false, ct);

    private async Task<IActionResult> SetYankAsync(
        string name, string version, bool yanked, CancellationToken ct)
    {
        string orgId = CurrentTenantId();

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }
        if (!token.HasCapability(Capabilities.YankCargo))
        {
            return Forbidden("yank:cargo capability required.");
        }

        if (!IsValidCrateName(name) || !PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }
        if (!PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid version.", Status = StatusCodes.Status400BadRequest });
        }

        // Resolve the org-scoped package + version. 404 for an unknown name/version so a yank
        // request can't probe another tenant's crate inventory.
        var pkg = await _packages.GetByPurlNameAsync(orgId, "cargo", name, ct);
        if (pkg is null)
        {
            return NotFound();
        }
        var ver = await _packages.GetVersionAsync(pkg.Id, version, ct);
        if (ver is null)
        {
            return NotFound();
        }

        await _packages.SetYankedAsync(ver.Id, yanked, ct);

        // Rewrite the stored index line's yanked flag so the sparse index reflects the state.
        // Round-trip through JsonNode so the rest of the line is preserved byte-for-byte except
        // the boolean; a malformed stored line is rebuilt minimally rather than left stale.
        string? stored = await _cargoMeta.GetIndexLineAsync(orgId, name, version, ct);
        if (stored is not null)
        {
            string updated = RewriteYankedFlag(stored, name, version, ver.ChecksumSha256, yanked);
            await _cargoMeta.UpdateIndexLineAsync(orgId, name, version, updated, ct);
        }

        // Per-version operator action → activity (not audit_log).
        await _audit.LogActivityAsync(orgId, "cargo", ver.Purl, yanked ? "yank" : "unyank",
            token.UserId, actorKind: token.ActorKind, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return new JsonResult(new { ok = true });
    }

    // ── Catch-all dispatcher ─────────────────────────────────────────────────

    /// <summary>
    /// GET /cargo/{**path} — dispatches to either the sparse index or the crate download
    /// handler based on the path shape.
    /// Download paths match <c>api/v1/crates/{name}/{version}/download</c>.
    /// All other paths are treated as sparse index file lookups.
    /// </summary>
    [HttpGet("/cargo/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> GetCatchAll(string path, CancellationToken ct)
    {
        // Download: api/v1/crates/{name}/{version}/download
        const string downloadPrefix = "api/v1/crates/";
        const string downloadSuffix = "/download";
        if (path.StartsWith(downloadPrefix, StringComparison.OrdinalIgnoreCase)
            && path.EndsWith(downloadSuffix, StringComparison.OrdinalIgnoreCase))
        {
            string inner = path[downloadPrefix.Length..^downloadSuffix.Length];
            int lastSlash = inner.LastIndexOf('/');
            if (lastSlash > 0)
            {
                string name = inner[..lastSlash];
                string version = inner[(lastSlash + 1)..];
                return await GetCrateAsync(name, version, ct);
            }
        }

        // Sparse index: the name is the last segment of the path
        int nameSlash = path.LastIndexOf('/');
        if (nameSlash >= 0)
        {
            string name = path[(nameSlash + 1)..];
            return await GetIndexAsync(name, ct);
        }

        return NotFound();
    }

    // ── Sparse index ─────────────────────────────────────────────────────────

    /// <summary>
    /// Serves the sparse index file for a crate. The response is a newline-delimited JSON
    /// document — one JSON object per version line, exactly as described by the Cargo sparse
    /// registry spec. Local versions shadow upstream versions on version collision.
    /// </summary>
    private async Task<IActionResult> GetIndexAsync(string name, CancellationToken ct)
    {
        if (!PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        // Collect local index lines for this crate.
        var localLines = await _cargoMeta.GetIndexLinesAsync(orgId, name, ct);

        // A reserved crate name behaves like a local_only claim: skip the upstream merge so only
        // locally-published versions are advertised, closing the dependency-confusion window.
        bool upstreamAllowed = settings.ProxyPassthroughEffective
            && !await _reserved.IsReservedAsync(orgId, "cargo", name, ct);
        var upstreamLines = upstreamAllowed
            ? await CollectUpstreamIndexLinesAsync(orgId, name, ParseLocalVersions(localLines), ct)
            : new List<string>();

        if (localLines.Count == 0 && upstreamLines.Count == 0)
        {
            return NotFound();
        }

        var allLines = new List<string>(localLines.Count + upstreamLines.Count);
        allLines.AddRange(localLines);
        allLines.AddRange(upstreamLines);

        string body = string.Join('\n', allLines);

        // The index body is built from local + upstream index lines for a fixed version set —
        // no timestamps — so the strong ETag is naturally stable across polls for an unchanged
        // crate. Cargo polls index files frequently; honouring If-None-Match returns 304 and
        // cuts bandwidth on the common no-change poll.
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        string etag = ComputeETagFromBytes(bodyBytes);
        if (Request.Headers.IfNoneMatch.FirstOrDefault() == etag)
        {
            Response.Headers.ETag = etag;
            return StatusCode(StatusCodes.Status304NotModified);
        }
        Response.Headers.ETag = etag;
        // Proxy-merged responses may include upstream lines that change as the upstream
        // publishes; short TTL so additions propagate. Local-only responses (passthrough off)
        // change only on local publish; a longer TTL is appropriate.
        Response.Headers.CacheControl = upstreamLines.Count > 0
            ? "private, max-age=60"
            : "private, max-age=300";
        return Content(body, "text/plain");
    }

    /// <summary>
    /// Computes a strong ETag over the response body. Mirrors the Maven metadata ETag shape:
    /// SHA-256 of the bytes, truncated to 16 hex chars, quoted.
    /// </summary>
    private static string ComputeETagFromBytes(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }

    /// <summary>
    /// Parses the local version set from the local index lines so upstream versions can be
    /// shadowed on collision.
    /// </summary>
    private static HashSet<string> ParseLocalVersions(IReadOnlyList<string> localLines)
    {
        var localVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in localLines)
        {
            string? vers = ParseVersionFromIndexLine(line);
            if (vers is not null)
            {
                localVersions.Add(vers);
            }
        }
        return localVersions;
    }

    /// <summary>
    /// Fetches the sparse index for a crate from the configured upstreams in priority order,
    /// returning the lines from the first upstream that responds. Lines whose version already
    /// exists locally are excluded so local versions shadow upstream on collision.
    /// </summary>
    private async Task<List<string>> CollectUpstreamIndexLinesAsync(
        string orgId, string name, HashSet<string> localVersions, CancellationToken ct)
    {
        var upstreamLines = new List<string>();
        var upstreamUrls = await _registries.ResolveAsync(orgId, "cargo", ct);
        foreach (string upstreamBase in upstreamUrls)
        {
            string? fetched = await FetchUpstreamIndexAsync(upstreamBase, name, ct);
            if (fetched is null)
            {
                continue;
            }

            // Only include upstream lines for versions not already in local store.
            foreach (string line in fetched.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                string? vers = ParseVersionFromIndexLine(line);
                if (vers is not null && !localVersions.Contains(vers))
                {
                    upstreamLines.Add(line);
                }
            }
            break;
        }
        return upstreamLines;
    }

    // ── Crate download ───────────────────────────────────────────────────────

    /// <summary>
    /// Serves a .crate file. Checks the blob store first (cache hit); on a miss, fetches
    /// from the upstream download URL, stores the bytes, and serves them. The SHA-256 of
    /// the downloaded bytes is captured and stored on the package_versions row.
    /// </summary>
    private async Task<IActionResult> GetCrateAsync(string name, string version, CancellationToken ct)
    {
        if (!PathSafeValidator.ValidateUpstreamSegment(name, "crate").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid crate name.", Status = StatusCodes.Status400BadRequest });
        }
        if (!PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid)
        {
            return BadRequest(new ProblemDetails { Detail = "Invalid version.", Status = StatusCodes.Status400BadRequest });
        }

        string orgId = CurrentTenantId();
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        var token = await ResolveCargoTokenAsync(orgId, ct);
        if (!settings!.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"cargo\"";
            return Unauthorized();
        }

        // A hosted (published) crate stores its blob under the publish pipeline's hosted key
        // (BlobKeys.Hosted), recorded on the package_versions row; a proxied crate stores under
        // the content-addressed BlobKeys.Cargo key. Prefer the stored row key so both shapes
        // resolve, falling back to the reconstructed Cargo key for any row that predates the
        // hosted-publish path. A yanked version is still downloadable — yank hides a version
        // from resolution, it does not delete the artefact.
        string blobKey = await ResolveLocalBlobKeyAsync(orgId, name, version, ct)
            ?? BlobKeys.Cargo(orgId, name, version);
        string storeKey = BlobKeys.StoreKey(blobKey);

        // Cache hit path.
        if (await _blobs.ExistsAsync(storeKey, ct))
        {
            var cachedStream = await _blobs.GetAsync(storeKey, ct);
            if (cachedStream is not null)
            {
                // deepcode ignore LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment
                // before reaching this path; Serilog renders structured parameters, not concatenated strings.
                _logger.LogDebug(
                    "Cargo cache hit: {Name} {Version} for org {OrgId}.", name, version, orgId);
                // A cached blob may be a hosted (published) crate or a proxied one; only
                // proxied accesses belong in the shared cache index. Gate on the version's
                // origin so hosted crates stay out of cache_artifact / tenant_artifact_access.
                await RecordProxiedCacheHitAsync(orgId, name, version, storeKey, ct);
                return File(cachedStream, "application/octet-stream", $"{name}-{version}.crate");
            }
        }

        // Cache miss — proxy fetch. A reserved crate name refuses the upstream fetch (local_only
        // semantics), so an unpublished reserved coordinate 404s instead of pulling from crates.io.
        if (!settings.ProxyPassthroughEffective
            || await _reserved.IsReservedAsync(orgId, "cargo", name, ct))
        {
            return NotFound();
        }

        var upstreamUrls = await _registries.ResolveAsync(orgId, "cargo", ct);
        return upstreamUrls.Count == 0
            ? NotFound()
            : await ProxyCrateFromUpstreamAsync(orgId, name, version, blobKey, upstreamUrls, ct);
    }

    // Walks the configured upstream URLs in priority order, fetching the crate from the first
    // that responds. On a checksum mismatch the walk stops immediately (supply-chain integrity
    // failure). On transient errors (network, SSRF, size), the next upstream is tried.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Functional Snyk // deepcode ignore suppression marker, not commented-out code.")]
    private async Task<IActionResult> ProxyCrateFromUpstreamAsync(
        string orgId, string name, string version, string blobKey,
        IReadOnlyList<string> upstreamUrls, CancellationToken ct)
    {
        foreach (string upstreamBase in upstreamUrls)
        {
            string downloadUrl = BuildCrateDownloadUrl(upstreamBase, name, version);
            var checksumSpec = await ResolveUpstreamChecksumSpecAsync(upstreamBase, name, version, ct);

            Stream crateStream;
            try
            {
                // Route through UpstreamClient: size-capped, SSRF-checked, checksum-verified
                // (when the index advertises a cksum), and dedup-protected. The blob is
                // stored under the org-scoped Cargo key so subsequent ExistsAsync calls hit
                // the cache path above.
                // deepcode ignore PT,LogForging: name and version are validated by PathSafeValidator.ValidateUpstreamSegment above;
                // blobKey comes from BlobKeys.Cargo (no traversal possible); Serilog uses structured rendering.
                (crateStream, _) = await _upstream.GetOrFetchStreamAsync(
                    blobKey, downloadUrl, checksumSpec, "cargo", orgId, ct: ct);
            }
            catch (ChecksumException)
            {
                // Index-advertised checksum and downloaded bytes disagree — a supply-chain
                // integrity failure. Fail loudly; the mismatch deserves operator attention.
                // deepcode ignore LogForging: name and version pass PathSafeValidator; downloadUrl is constructed from validated segments; Serilog structured rendering prevents log injection.
                _logger.LogWarning(
                    "Cargo crate checksum mismatch for {Name} {Version} from {Url}: index cksum does not match downloaded bytes.",
                    name, version, downloadUrl);
                return StatusCode(StatusCodes.Status502BadGateway, new ProblemDetails
                {
                    Detail = "Upstream crate failed checksum verification against its index entry.",
                    Status = StatusCodes.Status502BadGateway,
                });
            }
            catch (Exception ex) when (
                ex is HttpRequestException
                    or SsrfBlockedException
                    or UpstreamResponseTooLargeException
                    or TaskCanceledException
                    or OperationCanceledException)
            {
                // deepcode ignore LogForging: name and version pass PathSafeValidator; downloadUrl is constructed from
                // validated segments; ExceptionType is a type name, not user input; Serilog structured rendering prevents log injection.
                _logger.LogWarning(
                    "Cargo upstream crate fetch failed for {Name} {Version} from {Url}: {ExceptionType}",
                    name, version, downloadUrl, ex.GetType().Name);
                continue;
            }

            byte[] crateBytes;
            await using (crateStream)
            {
                using var ms = new MemoryStream();
                await crateStream.CopyToAsync(ms, ct);
                crateBytes = ms.ToArray();
            }

            string sha256Hex = ComputeSha256Hex(crateBytes);
            await RecordProxiedVersionAsync(orgId, name, version, blobKey, sha256Hex, crateBytes.Length, ct);

            // Record the proxy first-fetch into the shared cache index so the eviction
            // pipeline and vulnerability-response query can see it. Best-effort — the
            // recorder swallows its own failures.
            await _cacheRecorder.RecordAccessAsync(
                new CacheAccess(orgId, "cargo", name, version, $"{name}-{version}.crate",
                    sha256Hex, crateBytes.Length, blobKey, downloadUrl), ct);

            // deepcode ignore LogForging: name and version pass PathSafeValidator; sha256Hex is a hex digest from ComputeSha256Hex; Serilog structured rendering prevents log injection.
            _logger.LogInformation(
                "Cargo proxy first-fetch: {Name} {Version} ({Bytes} bytes, sha256={Sha256}) for org {OrgId}.",
                name, version, crateBytes.Length, sha256Hex[..ETagHexPrefixLength], orgId);

            return File(crateBytes, "application/octet-stream", $"{name}-{version}.crate");
        }

        return NotFound();
    }

    /// <summary>
    /// Returns the stored <c>blob_key</c> for a local crate version (proxy or hosted), or null
    /// when no local row exists. Tenant-scoped via the JOIN on <c>packages.org_id</c>. The
    /// hosted-publish path records the publish pipeline's hosted key here, which differs from
    /// the reconstructed content-addressed Cargo key, so the download path must consult the
    /// row rather than assume the key shape.
    /// </summary>
    private async Task<string?> ResolveLocalBlobKeyAsync(
        string orgId, string name, string version, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Tenant gate: packages.org_id = @orgId confines the lookup to the requesting org.
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT pv.blob_key
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = 'cargo'
              AND p.name = @name
              AND pv.version = @version
            """,
            new { orgId, name, version });
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves a Cargo auth token scoped to the given org. Cargo sends the token as a bare
    /// value in the Authorization header (no scheme prefix) — e.g. <c>Authorization: mytoken</c>
    /// — in addition to the standard <c>Authorization: Bearer mytoken</c> form.
    /// This helper tries Bearer/Basic first via the org-scoped extension, then falls back to
    /// treating the whole header value as a raw token and verifying org membership.
    /// Cross-org tokens are coerced to null so AnonymousPull governs cross-tenant requests
    /// consistently with the other ecosystems.
    /// </summary>
    private async Task<TokenRecord?> ResolveCargoTokenAsync(string orgId, CancellationToken ct)
    {
        // Standard Bearer / Basic resolution — org-scoped: cross-tenant tokens become null.
        var resolved = await Request.ResolveTokenAsync(_tokens, orgId, ct);
        if (resolved is not null)
        {
            return resolved;
        }

        // Cargo-specific: bare token with no scheme prefix.
        string? auth = Request.Headers.Authorization.FirstOrDefault();
        if (auth is null || auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                         || auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string raw = auth.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        var bareToken = await _tokens.ResolveAsync(raw, ct);
        // Reject tokens that belong to a different org — same coerce-to-null behaviour as
        // the org-scoped overload so AnonymousPull governs cross-tenant requests.
        return bareToken?.OrgId == orgId ? bareToken : null;
    }

    /// <summary>
    /// Fetches the sparse index file for a crate from the upstream registry via
    /// <see cref="UpstreamClient"/>. Returns the raw text content (newline-delimited JSON
    /// lines) on success, null on 404 or error. Routes through UpstreamClient to enforce
    /// the size cap and SSRF allowlist on metadata responses.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Functional Snyk // deepcode ignore suppression marker, not commented-out code.")]
    private async Task<string?> FetchUpstreamIndexAsync(
        string upstreamBase, string name, CancellationToken ct)
    {
        string indexPath = IndexPath(name);
        string url = $"{upstreamBase}/{indexPath}";
        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(url, ct);
            return response.IsSuccessStatusCode
                ? response.BodyAsString()
                : null;
        }
        catch (Exception ex) when (
            ex is HttpRequestException
                or SsrfBlockedException
                or UpstreamResponseTooLargeException
                or TaskCanceledException
                or OperationCanceledException)
        {
            // deepcode ignore LogForging: name passes PathSafeValidator; url comes from operator-configured upstream registry;
            // ExceptionType is a type name; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo upstream index fetch failed for {Name} from {Url}: {ExceptionType}",
                name, url, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Constructs the upstream crate download URL. For the crates.io sparse index
    /// (<c>index.crates.io</c>), the download base is <c>static.crates.io/crates</c>.
    /// For other sparse registries, <c>/api/v1/crates</c> is appended to the upstream base.
    /// </summary>
    private static string BuildCrateDownloadUrl(string upstreamBase, string name, string version)
    {
        string downloadBase = upstreamBase.Contains("index.crates.io", StringComparison.OrdinalIgnoreCase)
            ? "https://static.crates.io/crates"
            : $"{upstreamBase}/api/v1/crates";
        return $"{downloadBase}/{name}/{version}/download";
    }

    /// <summary>
    /// Records a proxied Cargo version in the packages/package_versions tables. Uses the
    /// standard GetOrCreate pattern so re-fetches are idempotent. Skips insertion when
    /// the version already exists (the blob was refreshed but the DB row is authoritative).
    /// </summary>
    private async Task RecordProxiedVersionAsync(
        string orgId, string name, string version,
        string blobKey, string sha256Hex, long sizeBytes,
        CancellationToken ct)
    {
        string purl = PurlNormalizer.Cargo(name, version);

        var pkg = await _packages.GetOrCreateAsync(orgId, "cargo", name, name, isProxy: true, ct);

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: package_id is derived from pkg.Id which is already org-scoped above.
        int existing = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = @pkgId AND version = @version",
            new { pkgId = pkg.Id, version });

        if (existing > 0)
        {
            return;
        }

        string filename = $"{name}-{version}.crate";
        // xtenant: package_id is derived from pkg.Id which is already org-scoped by GetOrCreateAsync above.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes,
                 checksum_sha256, first_fetch, origin)
            VALUES
                (@id, @pkgId, @version, @purl, @blobKey, @filename, @sizeBytes,
                 @sha256, 1, 'proxy')
            ON CONFLICT DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pkgId = pkg.Id,
                version,
                purl,
                blobKey,
                filename,
                sizeBytes,
                sha256 = sha256Hex,
            });
    }

    /// <summary>
    /// On a cache hit, records the access into the shared cache index — but only when the
    /// cached version was proxied. Hosted (published) crates are durable registry artefacts
    /// and never belong in <c>cache_artifact</c> / <c>tenant_artifact_access</c>. Looks up
    /// the version's origin, checksum, and size from <c>package_versions</c> (org-scoped via
    /// the join on <c>packages</c>) and forwards to the best-effort recorder. A lookup that
    /// finds no proxied row is a no-op; the recorder swallows any recording failure itself.
    /// </summary>
    private async Task RecordProxiedCacheHitAsync(
        string orgId, string name, string version, string blobKey, CancellationToken ct)
    {
        ProxiedVersionRow? row;
        try
        {
            await using var conn = await _db.OpenAsync(ct);
            row = await conn.QuerySingleOrDefaultAsync<ProxiedVersionRow>(
                """
                SELECT pv.origin AS Origin,
                       pv.checksum_sha256 AS ChecksumSha256,
                       pv.size_bytes AS SizeBytes
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.org_id = @orgId
                  AND p.ecosystem = 'cargo'
                  AND p.purl_name = @name
                  AND pv.version = @version
                """,
                new { orgId, name, version });
        }
        catch (Exception ex)
        {
            // The bytes already streamed to the client; this index lookup is best-effort.
            // deepcode ignore LogForging: name and version pass PathSafeValidator; ExceptionType is a type name; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo cache-hit recording lookup failed for {Name} {Version} (org {OrgId}): {ExceptionType}",
                name, version, orgId, ex.GetType().Name);
            return;
        }

        if (row is null || !string.Equals(row.Origin, "proxy", StringComparison.Ordinal))
        {
            return;
        }

        // upstream_url is left null on a hit: the originating upstream is not known here and
        // the row already carries it from the first-fetch insert.
        await _cacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, "cargo", name, version, $"{name}-{version}.crate",
                row.ChecksumSha256 ?? "", row.SizeBytes, blobKey, null), ct);
    }

    private sealed record ProxiedVersionRow(string Origin, string? ChecksumSha256, long SizeBytes);

    /// <summary>Parses the <c>vers</c> field from a Cargo index JSON line.</summary>
    private static string? ParseVersionFromIndexLine(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            return doc.RootElement.TryGetProperty("vers", out var v) ? v.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the index-advertised SHA-256 for a crate version by reading the upstream
    /// sparse index file (served from the metadata cache when warm) and extracting the
    /// matching line's <c>cksum</c>. Returns null when the index is unreachable, the
    /// version has no line, or the cksum is not a 64-char hex digest — the download then
    /// proceeds unverified, exactly as a registry that omits cksum would behave.
    /// </summary>
    private async Task<ChecksumSpec?> ResolveUpstreamChecksumSpecAsync(
        string upstreamBase, string name, string version, CancellationToken ct)
    {
        string? indexText = await FetchUpstreamIndexAsync(upstreamBase, name, ct);
        if (indexText is null)
        {
            return null;
        }

        string? cksum = ParseCksumForVersion(indexText, version);
        if (cksum is null)
        {
            return null;
        }

        if (cksum.Length != Sha256HexLength || !cksum.All(Uri.IsHexDigit))
        {
            // deepcode ignore LogForging: name and version pass PathSafeValidator; Serilog structured rendering prevents log injection.
            _logger.LogWarning(
                "Cargo index cksum for {Name} {Version} is not a SHA-256 hex digest; downloading unverified.",
                name, version);
            return null;
        }

        return new ChecksumSpec(ChecksumAlgorithm.Sha256, cksum.ToLowerInvariant());
    }

    /// <summary>Extracts the <c>cksum</c> field of the index line whose <c>vers</c> matches.</summary>
    private static string? ParseCksumForVersion(string indexText, string version)
    {
        foreach (string line in indexText.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (doc.RootElement.TryGetProperty("vers", out var v)
                    && v.GetString() == version
                    && doc.RootElement.TryGetProperty("cksum", out var c))
                {
                    return c.GetString();
                }
            }
            catch (JsonException)
            {
                // Malformed line — skip; other lines may still match.
            }
        }

        return null;
    }

    private static string ComputeSha256Hex(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Reads the request body fully, bounded by <paramref name="cap"/>. Returns null when the
    /// body exceeds the cap (the caller maps this to 413), so an oversized upload is rejected
    /// without materialising more than the cap's worth of bytes.
    /// </summary>
    private async Task<byte[]?> ReadBodyBoundedAsync(long cap, CancellationToken ct)
    {
        var limited = new LimitedReadStream(Request.Body, cap, "cargo publish frame");
        try
        {
            using var ms = new MemoryStream();
            await limited.CopyToAsync(ms, ct);
            return ms.ToArray();
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// Validates a Cargo crate name: 1–64 characters, ASCII alphanumeric plus '-' and '_'.
    /// The Cargo spec compares names case-insensitively and treats '-'/'_' as interchangeable;
    /// names land verbatim in path positions (index path, blob key), so the charset is locked
    /// down here on top of the traversal/control-char guard in PathSafeValidator.
    /// </summary>
    private static bool IsValidCrateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxCrateNameLength)
        {
            return false;
        }
        foreach (char c in name)
        {
            bool ok = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z')
                or (>= '0' and <= '9') or '-' or '_';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Returns the stored index line with its <c>yanked</c> flag set to
    /// <paramref name="yanked"/>. Parses the line as JSON and flips the one property, leaving
    /// every other field untouched. A line that no longer parses (corrupted at rest) is rebuilt
    /// from the known name/version/cksum with an empty dependency/feature set so the index stays
    /// well-formed rather than serving a broken line.
    /// </summary>
    private static string RewriteYankedFlag(
        string storedLine, string name, string version, string? cksum, bool yanked)
    {
        try
        {
            if (JsonNode.Parse(storedLine) is JsonObject obj)
            {
                obj["yanked"] = yanked;
                return obj.ToJsonString(CargoPublishJsonContext.CompactOptions);
            }
        }
        catch (JsonException)
        {
            // Fall through to the minimal rebuild below.
        }

        var rebuilt = new JsonObject
        {
            ["name"] = name,
            ["vers"] = version,
            ["deps"] = new JsonArray(),
            ["cksum"] = cksum ?? "",
            ["features"] = new JsonObject(),
            ["yanked"] = yanked,
        };
        return rebuilt.ToJsonString(CargoPublishJsonContext.CompactOptions);
    }

    private static ObjectResult Forbidden(string detail)
        => new(new ProblemDetails { Detail = detail, Status = StatusCodes.Status403Forbidden })
        { StatusCode = StatusCodes.Status403Forbidden };

    private static ObjectResult Payload413(string detail)
        => new(new ProblemDetails { Detail = detail, Status = StatusCodes.Status413PayloadTooLarge })
        { StatusCode = StatusCodes.Status413PayloadTooLarge };
}
