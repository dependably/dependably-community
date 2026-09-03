using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// The Hex repository read plane at <c>/hex/</c>: the four signed registry resources, package
/// and documentation tarballs, and the org's public key — what Mix and Rebar3 resolve and fetch
/// from. Every registry resource is rebuilt from what this org holds plus a verified upstream
/// answer, signed with the org's own key under the repository name <see cref="HexIndexBuilder.RepositoryName"/>,
/// because a Hex client checks both the signature and the embedded repository name and a
/// relabelled upstream byte stream can satisfy neither. The API plane (<c>/hex/api/</c>) is
/// <see cref="HexApiController"/>.
/// </summary>
[ApiController]
public sealed partial class HexController : OrgScopedControllerBase
{
    private const string Ecosystem = "hex";
    private const string ProtobufContentType = "application/octet-stream";

    private readonly HexControllerServices _svc;

    public HexController(HexControllerServices svc) => _svc = svc;

    // One catch-all because the /repos/{name}/… alias prefixes every resource and the tarball
    // and docs names contain a version that can carry dots and hyphens; "download" is the
    // tarball's cost, the dominant one, while the metadata reads are single-flighted and
    // TTL-cached through UpstreamClient.
    [HttpGet("/hex/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> HandleRepositoryRequest(string? path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith("api/", StringComparison.Ordinal) || path == "api")
        {
            return NotFound();
        }

        // The organization form: hex_core rewrites every resource to /repos/<org>/… when the
        // client configured the repository as an organization. Both spellings name this org's
        // one repository, so the alias is accepted only for the repository name this registry
        // signs under and stripped; any other name is a repository that does not exist here.
        if (path.StartsWith("repos/", StringComparison.Ordinal))
        {
            string rest = path["repos/".Length..];
            int slash = rest.IndexOf('/');
            if (slash <= 0 || rest[..slash] != HexIndexBuilder.RepositoryName)
            {
                return NotFound();
            }

            path = rest[(slash + 1)..];
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, ct);
        if (token is not null && token.OrgId != orgId)
        {
            token = null;
        }

        if (!TryClassify(path, out var request))
        {
            return NotFound();
        }

        // Every resource is tenant data: the index names what this org holds and the tarballs
        // are its bytes. AnonymousPull opens all of it, the same switch every ecosystem honours;
        // a token that is present must carry the read capability for what it asks — metadata
        // for the signed index resources and the public key, artifact for tarballs and docs.
        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"hex\"";
            return Unauthorized();
        }

        string required = request.Kind is ResourceKind.Tarball or ResourceKind.Docs
            ? Capabilities.ReadArtifact
            : Capabilities.ReadMetadata;
        return token is not null && !token.HasCapability(required)
            ? StatusCode(StatusCodes.Status403Forbidden, $"{required} capability required.")
            : await DispatchAsync(request, orgId, settings, token, ct);
    }

    private enum ResourceKind
    {
        PublicKey,
        Names,
        Versions,
        Package,
        Tarball,
        Docs,
        Policy,
    }

    private readonly record struct ResourceRequest(ResourceKind Kind, string Name, string Version);

    private async Task<IActionResult> DispatchAsync(
        ResourceRequest request, string orgId, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        // An edge holds no signing key: the five signed resources are its master's bytes, passed
        // through unchanged so a client registered against the master verifies either node.
        return _svc.Edge.IsEdge && request.Kind is not (ResourceKind.Tarball or ResourceKind.Docs)
            ? await ServeFromMasterAsync(request, orgId, ct)
            : request.Kind switch
            {
                ResourceKind.PublicKey => await ServePublicKeyAsync(orgId, ct),
                ResourceKind.Names => await ServeNamesAsync(orgId, ct),
                ResourceKind.Versions => await ServeVersionsAsync(orgId, settings, ct),
                ResourceKind.Package => await ServePackageAsync(orgId, request.Name, settings, ct),
                ResourceKind.Tarball => await ServeTarballAsync(orgId, request.Name, request.Version, settings, token, ct),
                ResourceKind.Docs => await ServeDocsAsync(orgId, request.Name, request.Version, settings, token, ct),
                _ => await ServePolicyAsync(orgId, request.Name, settings, ct),
            };
    }

    private static bool TryClassify(string path, out ResourceRequest request)
    {
        request = default;
        switch (path)
        {
            case "public_key": request = new ResourceRequest(ResourceKind.PublicKey, "", ""); return true;
            case "names": request = new ResourceRequest(ResourceKind.Names, "", ""); return true;
            case "versions": request = new ResourceRequest(ResourceKind.Versions, "", ""); return true;
            default: break;
        }

        if (TryParseSingleSegment(path, "packages/", out string packageName))
        {
            request = new ResourceRequest(ResourceKind.Package, packageName, "");
            return true;
        }

        if (TryParseCoordinate(path, "tarballs/", ".tar", out string tarName, out string tarVersion))
        {
            request = new ResourceRequest(ResourceKind.Tarball, tarName, tarVersion);
            return true;
        }

        if (TryParseCoordinate(path, "docs/", ".tar.gz", out string docsName, out string docsVersion))
        {
            request = new ResourceRequest(ResourceKind.Docs, docsName, docsVersion);
            return true;
        }

        if (TryParseSingleSegment(path, "policies/", out string policyName))
        {
            request = new ResourceRequest(ResourceKind.Policy, policyName, "");
            return true;
        }

        return false;
    }

    // ── Signed resources ─────────────────────────────────────────────────────

    private async Task<IActionResult> ServePublicKeyAsync(string orgId, CancellationToken ct)
    {
        var key = await _svc.SigningKeys.GetOrCreateAsync(orgId, ct);
        if (key is null)
        {
            return SigningUnavailable();
        }

        using (key)
        {
            Response.Headers.CacheControl = "private, max-age=300";
            return Content(key.PublicKeyPem, "text/plain");
        }
    }

    private async Task<IActionResult> ServeNamesAsync(string orgId, CancellationToken ct)
    {
        var held = await _svc.Releases.ListAllAsync(orgId, ct);
        return await SignAndServeAsync(orgId, HexRegistryCodec.EncodeNames(HexIndexBuilder.BuildNames(held)), ct);
    }

    private async Task<IActionResult> ServeVersionsAsync(string orgId, OrgSettings? settings, CancellationToken ct)
    {
        var held = await _svc.Releases.ListAllAsync(orgId, ct);
        var blocked = new HashSet<(string, string)>();
        foreach (string name in held.Select(h => h.Name).Distinct(StringComparer.Ordinal))
        {
            var blockedVersions = await BlockedHeldVersionsAsync(orgId, name, settings, ct);
            foreach (string v in blockedVersions)
            {
                blocked.Add((name, v));
            }
        }

        var advisories = await _svc.Advisories.ListForOwnersAsync(held.Select(h => h.Release.OwnerId).ToList(), ct);
        var owners = advisories.SelectMany(a => a.OwnerIds).ToHashSet(StringComparer.Ordinal);
        var versions = HexIndexBuilder.BuildVersions(held, blocked, owners);
        return await SignAndServeAsync(orgId, HexRegistryCodec.EncodeVersions(versions), ct);
    }

    private async Task<IActionResult> ServePackageAsync(string orgId, string name, OrgSettings? settings, CancellationToken ct)
    {
        if (!HexNaming.IsValidPackageName(name))
        {
            return NotFound();
        }

        var held = await _svc.Releases.ListForPackageAsync(orgId, name, ct);

        // A reserved name, or one ClaimResolver resolves to local_only, never consults the
        // upstream: only what this org holds is advertised, which closes the dependency-confusion
        // window the same way it is closed on every other ecosystem's index.
        bool upstreamAllowed = settings is { ProxyPassthroughEffective: true }
            && !await _svc.Reserved.IsReservedAsync(orgId, Ecosystem, name, ct)
            && await _svc.ClaimResolver.IsProxyFetchAllowedAsync(orgId, "hex", name, ct);
        var upstream = upstreamAllowed ? await FetchUpstreamPackageAsync(orgId, name, ct) : UpstreamPackageResult.Absent;

        if (held.Count == 0 && upstream.Package is null)
        {
            return upstream.Outcome == UpstreamOutcome.Fault
                ? StatusCode(StatusCodes.Status502BadGateway, "Upstream Hex repository is unavailable.")
                : NotFound();
        }

        if (settings is null)
        {
            // Absent policy never reads as "no policy": nothing is advertised.
            return NotFound();
        }

        var blocked = await BlockedHeldVersionsAsync(orgId, name, settings, ct);
        var advisories = await _svc.Advisories.ListForOwnersAsync(held.Select(h => h.OwnerId).ToList(), ct);
        var package = HexIndexBuilder.BuildPackage(
            name, held, upstream.Package, blocked, advisories, HexIndexBuilder.PolicyFrom(settings), _svc.Time.GetUtcNow());
        return package.Releases.Count == 0
            ? NotFound()
            : await SignAndServeAsync(orgId, HexRegistryCodec.EncodePackage(package), ct,
                cacheControl: upstream.Package is not null ? "private, max-age=60" : "private, max-age=300");
    }

    private async Task<IActionResult> SignAndServeAsync(string orgId, byte[] payload, CancellationToken ct, string cacheControl = "private, max-age=300")
    {
        var key = await _svc.SigningKeys.GetOrCreateAsync(orgId, ct);
        if (key is null)
        {
            return SigningUnavailable();
        }

        byte[] body;
        using (key)
        {
            body = HexRegistrySigner.BuildResource(payload, key.PrivateKey);
        }

        // PKCS#1 v1.5 is deterministic, so an unchanged resource re-signs to identical bytes and
        // the strong ETag holds across polls; hex_core sends if-none-match on every fetch.
        string etag = "\"" + Convert.ToHexString(SHA256.HashData(body))[..32].ToLowerInvariant() + "\"";
        Response.Headers.ETag = etag;
        Response.Headers.CacheControl = cacheControl;
        return Request.Headers.IfNoneMatch.Any(v => v == etag)
            ? StatusCode(StatusCodes.Status304NotModified)
            : File(body, ProtobufContentType);
    }

    private ObjectResult SigningUnavailable() =>
        StatusCode(StatusCodes.Status503ServiceUnavailable,
            _svc.Edge.IsEdge
                ? "Hex registry signing is unavailable: an edge node serves its master's signed resources and holds no key of its own."
                : "Hex registry signing is unavailable: this instance has no DEPENDABLY_MASTER_KEY, so no signing key can be stored.");

    // ── Upstream package ─────────────────────────────────────────────────────

    private enum UpstreamOutcome
    {
        Ok,
        Absent,
        Fault,
    }

    private readonly record struct UpstreamPackageResult(HexPackage? Package, UpstreamOutcome Outcome, UpstreamSource? Source)
    {
        public static UpstreamPackageResult Absent => new(null, UpstreamOutcome.Absent, null);
    }

    private async Task<UpstreamPackageResult> FetchUpstreamPackageAsync(string orgId, string name, CancellationToken ct)
    {
        var result = await HexUpstreamPackageFetcher.FetchAsync(
            _svc.Upstream, _svc.Registries, orgId, name, _svc.Logger, _svc.MasterKeys, ct);
        return new UpstreamPackageResult(result.Package, result.Outcome switch
        {
            HexUpstreamOutcome.Ok => UpstreamOutcome.Ok,
            HexUpstreamOutcome.Fault => UpstreamOutcome.Fault,
            _ => UpstreamOutcome.Absent,
        }, result.Source);
    }

    // ── Block gate on held versions ──────────────────────────────────────────

    // The versions this org holds on either plane and hard-blocks on their stored facts, so the
    // index never advertises a version the tarball route refuses for a reason the index knows.
    private async Task<HashSet<string>> BlockedHeldVersionsAsync(string orgId, string name, OrgSettings? settings, CancellationToken ct)
    {
        var blocked = new HashSet<string>(StringComparer.Ordinal);
        var now = _svc.Time.GetUtcNow();

        var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, Ecosystem, name, ct);
        if (pkg is not null)
        {
            var uploaded = await _svc.Packages.GetVersionsAsync(pkg.Id, ct);
            if (uploaded.Count > 0)
            {
                if (settings is null)
                {
                    blocked.UnionWith(uploaded.Select(v => v.Version));
                }
                else
                {
                    var signals = await _svc.Vulns.GetGateSignalsBatchAsync(uploaded.Select(v => v.Id).ToList(), ct);
                    blocked.UnionWith(uploaded
                        .Where(v => BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
                        .Select(v => v.Version));
                }
            }
        }

        var cached = await _svc.CacheArtifacts.ListServeFactsForNameAsync(orgId, Ecosystem, name, ct);
        if (cached.Count == 0)
        {
            return blocked;
        }

        if (settings is null)
        {
            blocked.UnionWith(cached.Select(c => c.Version));
            return blocked;
        }

        var cacheSignals = await _svc.Vulns.GetGateSignalsBatchForCacheArtifactsAsync(cached.Select(c => c.Id).ToList(), ct);
        blocked.UnionWith(cached
            .Where(c => BlockGateService.IsHardBlockedByCacheEntry(c, settings, cacheSignals.GetValueOrDefault(c.Id), now))
            .Select(c => c.Version));
        return blocked;
    }

    // ── Path parsing ─────────────────────────────────────────────────────────

    private static bool TryParseSingleSegment(string path, string prefix, out string segment)
    {
        segment = "";
        if (!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string rest = path[prefix.Length..];
        if (rest.Length == 0 || rest.Contains('/') || !PathSafeValidator.ValidateUpstreamSegment(rest, "name").IsValid)
        {
            return false;
        }

        segment = rest;
        return true;
    }

    // {name}-{version}{suffix}: the name is lower-case letters, digits and underscores (never a
    // hyphen), so the first hyphen is the separator.
    private static bool TryParseCoordinate(string path, string prefix, string suffix, out string name, out string version)
    {
        name = "";
        version = "";
        if (!path.StartsWith(prefix, StringComparison.Ordinal) || !path.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        string file = path[prefix.Length..^suffix.Length];
        int dash = file.IndexOf('-');
        if (dash <= 0 || dash == file.Length - 1 || file.Contains('/'))
        {
            return false;
        }

        name = file[..dash];
        version = file[(dash + 1)..];
        return HexNaming.IsValidPackageName(name)
            && HexNaming.IsValidVersion(version)
            && PathSafeValidator.ValidateUpstreamSegment(version, "version").IsValid;
    }
}

/// <summary>Scoped DI bundle for the Hex repository and API controllers.</summary>
public sealed record HexControllerServices(
    TokenRepository Tokens,
    OrgRepository Orgs,
    PackageRepository Packages,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    UpstreamRegistryResolver Registries,
    CacheAccessRecorder CacheRecorder,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    VulnerabilityRepository Vulns,
    ReservedNamespaceService Reserved,
    ClaimResolver ClaimResolver,
    BlocklistRepository Blocklist,
    BlockGateService BlockGate,
    ProxyFetchService ProxyFetch,
    HexSigningKeyRepository SigningKeys,
    HexReleaseRepository Releases,
    HexAdvisoryRepository Advisories,
    TimeProvider Time,
    ILogger<HexController> Logger,
    IEdgeMode Edge,
    HexMasterKeyResolver MasterKeys);
