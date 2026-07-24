using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Webhooks;
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
// Full Cargo protocol surface (sparse index, crate download/publish/yank, owners); the real
// remedy for the coupling is per-concern handler extraction, a separate architectural change.
[SuppressMessage("Major Code Smell", "S1200:Classes should not be coupled to too many other classes",
    Justification = "Full Cargo protocol surface; coupling is inherent and the remedy is handler extraction, a separate change.")]
public sealed partial class CargoController : OrgScopedControllerBase
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
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _tenantAccess;
    private readonly VulnerabilityRepository _vulns;
    private readonly TimeProvider _time;
    private readonly IPackagePublishService _publish;
    private readonly IUploadLimitResolver _uploadLimits;
    private readonly ClaimResolver _claimResolver;
    private readonly ReservedNamespaceService _reserved;
    private readonly AuditRepository _audit;
    private readonly IPackageEventSink _eventSink;
    private readonly EdgePublishGuard _edgeGuard;
    private readonly BlockGateService _blockGate;
    private readonly LicenseRepository _licenses;
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
        CacheArtifactRepository cacheArtifacts,
        TenantArtifactAccessRepository tenantAccess,
        VulnerabilityRepository vulns,
        TimeProvider time,
        IPackagePublishService publish,
        IUploadLimitResolver uploadLimits,
        ClaimResolver claimResolver,
        ReservedNamespaceService reserved,
        AuditRepository audit,
        IPackageEventSink eventSink,
        EdgePublishGuard edgeGuard,
        BlockGateService blockGate,
        LicenseRepository licenses,
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
        _cacheArtifacts = cacheArtifacts;
        _tenantAccess = tenantAccess;
        _vulns = vulns;
        _time = time;
        _publish = publish;
        _uploadLimits = uploadLimits;
        _claimResolver = claimResolver;
        _reserved = reserved;
        _audit = audit;
        _eventSink = eventSink;
        _edgeGuard = edgeGuard;
        _blockGate = blockGate;
        _licenses = licenses;
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
            // installable version. Combines uploaded (package_versions) and global-plane proxy
            // (cache_artifact) versions so proxy-cached crates are represented. Falls back to
            // any version when all are yanked.
            string? maxVersion = await ResolveMaxVersionAsync(orgId, pkg.Id, pkg.Name, ct);
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
    /// Resolves the latest non-yanked version for a crate across both uploaded
    /// (package_versions) and global-plane proxy (cache_artifact) versions. Falls back to
    /// the most recently created version when all versions are yanked. Returns null when the
    /// crate has no versions at all.
    /// </summary>
    private async Task<string?> ResolveMaxVersionAsync(string orgId, string packageId, string name, CancellationToken ct)
    {
        var uploadedVersions = await _packages.GetVersionsAsync(packageId, ct);
        var proxyEntries = await _cacheArtifacts.ListServeFactsForNameAsync(orgId, "cargo", name, ct);

        // Deduplicate: proxy entries whose version already appears in uploaded are skipped.
        IReadOnlyList<PackageVersion> versions;
        if (proxyEntries.Count == 0)
        {
            versions = uploadedVersions;
        }
        else
        {
            var uploadedVersionSet = uploadedVersions
                .Select(v => v.Version)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var proxyIds = proxyEntries.Select(e => e.Id).ToList();
            var proxySignals = proxyIds.Count > 0
                ? await _vulns.GetGateSignalsBatchForCacheArtifactsAsync(proxyIds, ct)
                : new Dictionary<string, VulnGateSignals>();

            var synthetic = proxyEntries
                .Where(e => !uploadedVersionSet.Contains(e.Version))
                .GroupBy(e => e.Version, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First().ToPackageVersionSynthetic(proxySignals))
                .ToList();

            var combined = new List<PackageVersion>(uploadedVersions.Count + synthetic.Count);
            combined.AddRange(uploadedVersions);
            combined.AddRange(synthetic);
            versions = combined;
        }

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
    [SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "ASP.NET Core MVC does not invoke a static action method correctly; must stay an instance method.")]
    public IActionResult AddOwners(string name)
        => OwnerMutationNotSupported();

    /// <summary>
    /// DELETE /cargo/api/v1/crates/{name}/owners — remove an owner. Owner mutation is not
    /// supported in this registry; access is governed by org membership managed through the
    /// registry's user management API. Returns 501 with an explicit message.
    /// </summary>
    [HttpDelete("/cargo/api/v1/crates/{name}/owners")]
    [EnableRateLimiting("push")]
    [SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "ASP.NET Core MVC does not invoke a static action method correctly; must stay an instance method.")]
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

        // The publish envelope's license field is the cheapest license signal available — no
        // tarball parse needed. Extracted here (before the publish call) so the hard-block
        // gate inside StoreAndRecordAsync can evaluate it before the version row is persisted.
        // license-file carries no SPDX signal so it is not modelled.
        var declaredLicense = LicenseExtractor.FromCargoPublishLicense(args.Metadata.License);
        var presentation = LicenseExtractor.PresentationOnly(
            args.Metadata.Homepage, args.Metadata.Repository, args.Metadata.Description);
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
            Licenses = declaredLicense.Spdx.Count > 0 ? declaredLicense.Spdx : null,
            Homepage = presentation.Homepage,
            Repository = presentation.Repository,
            Description = presentation.Description,
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

        if (declaredLicense.Spdx.Count > 0)
        {
            await _licenses.SetLicensesAsync(versionId, declaredLicense.Spdx, "upstream", ct);
        }

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
        // Fail-closed on an edge node: yank/unyank flips an authoritative version flag + rewrites
        // the sparse index line a cache edge does not own, so it is refused here before any lookup.
        if (_edgeGuard.UploadRejection() is { } edgeReject)
        {
            return edgeReject;
        }

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

        // Webhook dispatch for yank (not unyank — subscribers track removals, not reinstatements).
        if (yanked)
        {
            var org = await _orgs.GetByIdAsync(orgId, ct);
            string orgSlug = org?.Slug ?? orgId;
            string payload = new PackageEvents.Yank("cargo", name, version, ver.Purl, Reason: null).ToJson();
            _eventSink.Dispatch(new PackageEventEnvelope(
                EventType: PackageEvents.TypeYank,
                OrgId: orgId,
                OrgSlug: orgSlug,
                Ecosystem: "cargo",
                Name: name,
                Version: version,
                Purl: ver.Purl,
                ArtifactHash: ver.ChecksumSha256 is null ? null : "sha256:" + ver.ChecksumSha256,
                Actor: token.UserId,
                OccurredAt: _time.GetUtcNow(),
                DataJson: payload));
        }

        return new JsonResult(new { ok = true });
    }

}
