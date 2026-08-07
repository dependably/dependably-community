using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Dependably.Api;

/// <summary>
/// Terraform provider mirror surface — implements the Provider Network Mirror Protocol so
/// <c>terraform init</c> resolves and downloads provider archives through Dependably.
///
/// Routes, all under <c>/terraform/</c> and keyed by the provider's fully-qualified source
/// address (<c>{hostname}/{namespace}/{type}</c>):
/// <c>/terraform/{hostname}/{namespace}/{type}/index.json</c> (version list),
/// <c>/terraform/{hostname}/{namespace}/{type}/{version}.json</c> (per-platform archives),
/// <c>/terraform/{hostname}/{namespace}/{type}/{version}/{os}_{arch}.zip</c> (the archive).
///
/// The archive URL in a version document is emitted relative to that document, as
/// <c>{version}/{os}_{arch}.zip</c>. The platform lives in its own path segment rather than in a
/// filename suffix because provider type names legitimately contain underscores, which makes
/// <c>terraform-provider-{type}_{version}_{os}_{arch}.zip</c> ambiguous to parse back into a
/// platform.
///
/// Proxy-only surface, like <see cref="GoController"/>: providers are fetched from the configured
/// upstream registries and cached. There is no hosted-publish path — Terraform's own publishing
/// flow targets a registry, and this is a mirror.
///
/// Serving is a two-host operation, unlike every other ecosystem here. The registry protocol
/// (<c>{upstream}/v1/providers/…</c>) resolves versions and hands back a <c>download_url</c> on a
/// separate host — <c>releases.hashicorp.com</c> for HashiCorp's own providers — which is where the
/// archive bytes actually come from. The registry response also carries a <c>shasum</c> per
/// platform, which becomes the <see cref="ChecksumSpec"/> the fetch path verifies, so the archive
/// host being discovered rather than configured does not mean the bytes are unverified.
///
/// An upstream may instead speak the network mirror protocol — this controller's own serving shape
/// — which is how an edge node chains its master. Such a row is marked
/// <c>upstream_protocol='mirror'</c>; the two protocols share no path, so the distinction is
/// carried explicitly rather than inferred from the URL. On that path the archive URL is resolved
/// relative to the version document and constrained to the configured base, and the checksum comes
/// from the <c>zh:</c> hash when the mirror publishes one.
///
/// Version documents publish the optional <c>hashes</c> field as a <c>zh:</c> entry — the archive's
/// SHA-256, which this instance already holds on the cache-plane row — for every platform it has
/// cached, and otherwise pass through the hashes an upstream mirror published. That is what gives a
/// chained node something to verify: a downstream edge takes its fetch-time checksum from exactly
/// this field, and the client-side <c>.terraform.lock.hcl</c> anchor that
/// <c>docs/adr/0003-terraform-provider-network-mirror.md</c> relies on does not protect an
/// intermediate cache. Terraform's own <c>h1:</c> dirhash is still not emitted: it is a different
/// computation over the extracted contents, and the lock file remains the client's anchor for it.
///
/// The upstream's <c>Authorization</c> credential is attached only to requests against the
/// configured upstream base authority — the mirror surface and the registry's own metadata
/// endpoints. The registry protocol's <c>download_url</c> names a host the upstream chose, not one
/// the operator configured, so sending the org's credential there would hand it to a third party.
/// </summary>
[ApiController]
public sealed class TerraformController : OrgScopedControllerBase
{
    private readonly TerraformControllerServices _svc;

    public TerraformController(TerraformControllerServices svc) => _svc = svc;

    private const string Ecosystem = "terraform";

    /// <summary>Applied when the org has set no OSV score tolerance of its own.</summary>
    private const double DefaultMaxOsvScoreTolerance = 10.0;

    /// <summary>Mirror documents are small JSON; the client re-reads them per init.</summary>
    private static readonly JsonSerializerOptions MirrorJson = new(JsonSerializerDefaults.Web);

    // ── Upstream registry protocol DTOs ──────────────────────────────────────
    // The provider registry protocol emits snake_case. These carry explicit property names
    // rather than relying on a serializer default, per the wire-format rule in CLAUDE.md.

    private sealed record UpstreamVersions(
        [property: JsonPropertyName("versions")] List<UpstreamVersion>? Versions);

    private sealed record UpstreamVersion(
        [property: JsonPropertyName("version")] string? Version,
        [property: JsonPropertyName("platforms")] List<UpstreamPlatform>? Platforms);

    private sealed record UpstreamPlatform(
        [property: JsonPropertyName("os")] string? Os,
        [property: JsonPropertyName("arch")] string? Arch);

    /// <summary>
    /// One platform of one version, as this controller serves it. Distinct from
    /// <see cref="UpstreamPlatform"/> because the mirror protocol carries hashes alongside each
    /// platform and the registry protocol does not, and those hashes are re-emitted downstream.
    /// </summary>
    private sealed record PlatformArchive(string Os, string Arch, List<string>? UpstreamHashes);

    private sealed record UpstreamDownload(
        [property: JsonPropertyName("download_url")] string? DownloadUrl,
        [property: JsonPropertyName("shasum")] string? Shasum,
        // The remaining fields carry the publisher-signed provenance chain. filename names the
        // archive's entry inside the SHASUMS document; shasums_url/shasums_signature_url are the
        // SHASUMS file and its detached OpenPGP signature TerraformProvenanceVerifier checks.
        // signing_keys is parsed for completeness but deliberately never consulted as a trust
        // root — see the class doc on TerraformProvenanceVerifier for why. Mirror-protocol
        // responses carry none of these (only DownloadUrl/Shasum), so they default to null.
        [property: JsonPropertyName("filename")] string? Filename = null,
        [property: JsonPropertyName("shasums_url")] string? ShasumsUrl = null,
        [property: JsonPropertyName("shasums_signature_url")] string? ShasumsSignatureUrl = null,
        [property: JsonPropertyName("signing_keys")] UpstreamSigningKeys? SigningKeys = null);

    private sealed record UpstreamSigningKeys(
        [property: JsonPropertyName("gpg_public_keys")] List<UpstreamGpgPublicKey>? GpgPublicKeys);

    private sealed record UpstreamGpgPublicKey(
        [property: JsonPropertyName("key_id")] string? KeyId,
        [property: JsonPropertyName("ascii_armor")] string? AsciiArmor);

    /// <summary>
    /// The one field this controller reads from the registry protocol's per-version metadata
    /// document (<c>/v1/providers/{ns}/{type}/{version}</c>): the upstream publish timestamp that
    /// feeds the release-age cooldown gate. The network mirror protocol carries no timestamp, so
    /// this is a registry-protocol-only fact.
    /// </summary>
    private sealed record UpstreamVersionMetadata(
        [property: JsonPropertyName("published_at")] string? PublishedAt);

    // ── Upstream network mirror protocol DTOs ────────────────────────────────
    // The shapes this controller itself serves, read back when an upstream is another mirror —
    // a chained Dependably, which is how an edge node reaches its master.

    private sealed record MirrorIndex(
        [property: JsonPropertyName("versions")] Dictionary<string, JsonElement>? Versions);

    private sealed record MirrorVersionDocument(
        [property: JsonPropertyName("archives")] Dictionary<string, MirrorArchive>? Archives);

    private sealed record MirrorArchive(
        [property: JsonPropertyName("url")] string? Url,
        [property: JsonPropertyName("hashes")] List<string>? Hashes);

    // ── Route entry point ────────────────────────────────────────────────────

    /// <summary>
    /// GET /terraform/{**path} — catch-all for the mirror surface. The path is classified at
    /// runtime into the three protocol documents; a catch-all is required because the provider
    /// source address itself contains slashes.
    ///
    /// <paramref name="path"/> is nullable because a catch-all matches zero segments: a request for
    /// the bare base URL reaches this action with nothing bound. Declaring it non-nullable makes
    /// <c>[ApiController]</c>'s implicit-required model validation answer 400 "The path field is
    /// required" before the action runs — unhelpful to a client probing the base, and it renders the
    /// empty-path guard below unreachable. 404 is the protocol's own answer for "not mirrored here".
    /// </summary>
    // The three protocol documents share one catch-all action because a provider source address
    // contains slashes, so they cannot be split across route templates and cannot carry separate
    // policies. "download" is the archive's cost, which is the dominant one; the metadata reads
    // are single-flighted and TTL-cached through UpstreamClient, so a runner fleet asking for the
    // same index does not multiply through to the upstream.
    [HttpGet("/terraform/{**path}")]
    [EnableRateLimiting("download")]
    public async Task<IActionResult> HandleMirrorRequest(string? path, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return NotFound();
        }

        string orgId = CurrentTenantId();
        var settings = await _svc.Orgs.GetSettingsAsync(orgId, ct);
        var token = await Request.ResolveTokenAsync(_svc.Tokens, orgId, ct);

        if (settings is not null && !settings.AnonymousPull && token is null)
        {
            Response.Headers.WWWAuthenticate = "Bearer realm=\"dependably\"";
            return Unauthorized();
        }

        return await DispatchAsync(path, orgId, settings, token, ct);
    }

    private async Task<IActionResult> DispatchAsync(
        string path, string orgId, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        if (!TryClassify(path, out var request))
        {
            return NotFound();
        }

        // A reserved namespace follows local_only semantics: it never pulls from upstream. For
        // Terraform the reserved name is the provider's source address, which is what a
        // dependency-confusion attempt would have to collide with. The check covers all three
        // documents, not just the archive: forwarding a reserved private source address to a public
        // registry to build a version list discloses the name and serves that registry's answer for
        // it — the opposite of local_only. Terraform is proxy-only, so there is no local plane to
        // fall back to and every document for a reserved address is a 404.
        bool reserved = await _svc.Reserved.IsReservedAsync(
            orgId, Ecosystem, ProviderName(request.Provider), ct);

        return reserved ? NotFound() : request.Kind switch
        {
            DocumentKind.VersionIndex =>
                await ServeVersionIndexAsync(orgId, request.Provider, settings, ct),
            DocumentKind.VersionDocument =>
                await ServeVersionDocumentAsync(orgId, request.Provider, request.Version, settings, ct),
            _ => await ServeArchiveAsync(
                orgId, request.Provider, request.Version, request.Platform, settings, token, ct),
        };
    }

    private enum DocumentKind
    {
        VersionIndex,
        VersionDocument,
        Archive,
    }

    /// <summary>Which protocol document a request path names, and the coordinates it carries.</summary>
    private readonly record struct DocumentRequest(
        DocumentKind Kind, ProviderAddress Provider, string Version, string Platform);

    /// <summary>
    /// Classifies a mirror path into one of the three protocol documents. Parsing is separated from
    /// serving so the provider address — and therefore the reserved-namespace decision — is known
    /// for every document before any upstream call is made.
    /// </summary>
    private static bool TryClassify(string path, out DocumentRequest request)
    {
        request = default;

        // index.json: {hostname}/{namespace}/{type}/index.json
        if (path.EndsWith("/index.json", StringComparison.Ordinal))
        {
            if (!TryParseProvider(path[..^"/index.json".Length], out var indexProvider))
            {
                return false;
            }

            request = new DocumentRequest(DocumentKind.VersionIndex, indexProvider, "", "");
            return true;
        }

        // archive: {hostname}/{namespace}/{type}/{version}/{os}_{arch}.zip
        if (path.EndsWith(".zip", StringComparison.Ordinal))
        {
            if (!TryParseArchive(path, out var archiveProvider, out string archiveVersion, out string platform))
            {
                return false;
            }

            request = new DocumentRequest(
                DocumentKind.Archive, archiveProvider, archiveVersion, platform);
            return true;
        }

        // version document: {hostname}/{namespace}/{type}/{version}.json
        if (!path.EndsWith(".json", StringComparison.Ordinal))
        {
            return false;
        }

        int slash = path.LastIndexOf('/');
        if (slash <= 0)
        {
            return false;
        }

        string version = path[(slash + 1)..^".json".Length];
        if (!TryParseProvider(path[..slash], out var provider) || !IsSafeSegment(version))
        {
            return false;
        }

        request = new DocumentRequest(DocumentKind.VersionDocument, provider, version, "");
        return true;
    }

    // ── Path parsing ─────────────────────────────────────────────────────────

    /// <summary>A provider's fully-qualified source address.</summary>
    internal readonly record struct ProviderAddress(string Hostname, string Namespace, string Type);

    /// <summary>
    /// Parses <c>{hostname}/{namespace}/{type}</c>. Every segment is validated as a path-safe
    /// upstream segment: these values reach blob keys and upstream URLs, so a traversal sequence
    /// or an embedded slash must not survive parsing.
    ///
    /// The three segments are lowercased here, and this is the only place a provider address enters
    /// the serve path — so the blob key, the cache-plane coordinate, the source pin and the PURL all
    /// derive from one canonical spelling. Terraform matches source addresses case-insensitively, so
    /// <c>hashicorp/random</c> and <c>HashiCorp/Random</c> are one provider; without this they would
    /// be two cache rows and two pins, and a block an operator recorded against one spelling would
    /// silently not apply to the other.
    /// </summary>
    internal static bool TryParseProvider(string s, out ProviderAddress provider)
    {
        provider = default;
        string[] parts = s.Split('/');
        if (parts.Length != 3 || Array.Exists(parts, p => !IsSafeSegment(p)))
        {
            return false;
        }

        provider = new ProviderAddress(
            parts[0].ToLowerInvariant(), parts[1].ToLowerInvariant(), parts[2].ToLowerInvariant());
        return true;
    }

    internal static bool TryParseArchive(
        string path, out ProviderAddress provider, out string version, out string platform)
    {
        provider = default;
        version = string.Empty;
        platform = string.Empty;

        // {hostname}/{namespace}/{type}/{version}/{os}_{arch}.zip
        string[] parts = path.Split('/');
        if (parts.Length != 5)
        {
            return false;
        }

        version = parts[3];
        platform = parts[4][..^".zip".Length];

        return IsSafeSegment(version)
            && IsSafeSegment(platform)
            && IsValidPlatform(platform)
            && TryParseProvider(string.Join('/', parts[0], parts[1], parts[2]), out provider);
    }

    private static bool IsSafeSegment(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && PathSafeValidator.ValidateUpstreamSegment(value, "segment").IsValid;

    /// <summary>
    /// True when a platform token is exactly <c>{os}_{arch}</c> with a non-empty os and arch. A
    /// bare or trailing underscore (<c>linux_</c>) passes <see cref="IsSafeSegment"/> and a plain
    /// <c>Contains('_')</c> check, then yields an empty arch that composes a malformed upstream
    /// <c>/download/{os}/</c> URL. Requiring an interior underscore rejects it before any fetch.
    /// </summary>
    private static bool IsValidPlatform(string platform)
    {
        int underscore = platform.IndexOf('_', StringComparison.Ordinal);
        return underscore > 0 && underscore < platform.Length - 1;
    }

    // ── Protocol documents ───────────────────────────────────────────────────

    /// <summary>
    /// Serves the version index. The document is a JSON object keyed by version string whose
    /// values are empty objects — the protocol reserves the value for future use and the client
    /// ignores its contents.
    ///
    /// When the upstream cannot answer — proxying is off, no upstream is configured, or the
    /// registry is unreachable — the index falls back to the versions this org already holds in
    /// the cache. That is the offline / egress-blocked case the mirror exists for: a provider whose
    /// archives are fully cached must stay resolvable, or <c>terraform init</c> fails on the very
    /// discovery step before it can reach the cached archive. Nothing cached leaves the upstream
    /// outcome standing, so a genuinely unknown provider is still a 404.
    /// </summary>
    private async Task<IActionResult> ServeVersionIndexAsync(
        string orgId, ProviderAddress provider, OrgSettings? settings, CancellationToken ct)
    {
        var versions = await FetchUpstreamVersionsAsync(orgId, provider, settings, ct);

        IReadOnlyCollection<string> versionStrings;
        if (versions.Value is not null)
        {
            versionStrings = versions.Value
                .Where(v => !string.IsNullOrWhiteSpace(v.Version))
                .Select(v => v.Version!)
                .ToList();
        }
        else
        {
            var local = await LocalVersionsAsync(orgId, provider, ct);
            if (local.Count == 0)
            {
                return UpstreamFailure(versions.Outcome);
            }

            versionStrings = local;
        }

        var index = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (string v in versionStrings)
        {
            index[v] = new { };
        }

        return Content(
            JsonSerializer.Serialize(new { versions = index }, MirrorJson), "application/json");
    }

    /// <summary>
    /// The provider versions this org holds a cached archive for. Restricted to rows whose blob key
    /// is this org's own — the same guard <see cref="CachedZipHashesAsync"/> applies — so a version
    /// listed here is one the org can actually serve an archive for, and a foreign tenant's global
    /// cache row does not inflate this org's index.
    /// </summary>
    private async Task<IReadOnlyCollection<string>> LocalVersionsAsync(
        string orgId, ProviderAddress provider, CancellationToken ct)
    {
        var rows = await _svc.CacheArtifacts.ListServeFactsForNameAsync(
            orgId, Ecosystem, ProviderName(provider), ct);

        var versions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (string.IsNullOrWhiteSpace(row.Version)
                || !row.Filename.EndsWith(".zip", StringComparison.Ordinal))
            {
                continue;
            }

            string platform = row.Filename[..^".zip".Length];
            string ownKey = BlobKeys.Terraform(
                orgId, provider.Hostname, provider.Namespace, provider.Type, row.Version, platform);
            if (string.Equals(row.BlobKey, ownKey, StringComparison.Ordinal))
            {
                versions.Add(row.Version);
            }
        }

        return versions;
    }

    /// <summary>
    /// Serves the per-version document listing one archive per platform the upstream registry
    /// advertises for that version. Archive URLs are relative to this document.
    ///
    /// Each archive carries a <c>hashes</c> entry when one is available: the <c>zh:</c> form of the
    /// SHA-256 this instance recorded when it cached the archive, falling back to whatever an
    /// upstream mirror published for that platform. A chained node takes its fetch-time checksum
    /// from this field and has no other source for one, so omitting it leaves the downstream cache
    /// verifying nothing.
    /// </summary>
    private async Task<IActionResult> ServeVersionDocumentAsync(
        string orgId, ProviderAddress provider, string version, OrgSettings? settings,
        CancellationToken ct)
    {
        var platforms = await FetchUpstreamPlatformsAsync(orgId, provider, version, settings, ct);

        var cachedHashes = await CachedZipHashesAsync(orgId, provider, version, ct);

        if (platforms.Value is null)
        {
            // Upstream could not answer. Serve the platforms this org already holds — each with the
            // zh: of the bytes it cached — so a cached provider version stays installable offline.
            // Nothing cached leaves the upstream outcome standing (404 for unknown, 502/503 fault).
            if (cachedHashes.Count == 0)
            {
                return UpstreamFailure(platforms.Outcome);
            }

            var localArchives = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (var (file, sha256) in cachedHashes)
            {
                string local = file[..^".zip".Length];
                localArchives[local] = new { url = $"{version}/{local}.zip", hashes = new[] { $"zh:{sha256}" } };
            }

            return Content(
                JsonSerializer.Serialize(new { archives = localArchives }, MirrorJson), "application/json");
        }

        var archives = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var p in platforms.Value)
        {
            if (string.IsNullOrWhiteSpace(p.Os) || string.IsNullOrWhiteSpace(p.Arch))
            {
                continue;
            }

            string platform = $"{p.Os}_{p.Arch}";
            string url = $"{version}/{platform}.zip";
            var hashes = cachedHashes.TryGetValue($"{platform}.zip", out string? sha256)
                ? [$"zh:{sha256}"]
                : p.UpstreamHashes;

            archives[platform] = hashes is { Count: > 0 }
                ? new { url, hashes }
                : (object)new { url };
        }

        return Content(
            JsonSerializer.Serialize(new { archives }, MirrorJson), "application/json");
    }

    /// <summary>
    /// The SHA-256 of every archive this instance already holds for one provider version, keyed by
    /// the cache-plane filename (<c>{os}_{arch}.zip</c>). One query per version document rather than
    /// one per platform: a provider commonly advertises a dozen platforms.
    /// </summary>
    private async Task<Dictionary<string, string>> CachedZipHashesAsync(
        string orgId, ProviderAddress provider, string version, CancellationToken ct)
    {
        var rows = await _svc.CacheArtifacts.ListServeFactsForNameAsync(
            orgId, Ecosystem, ProviderName(provider), ct);

        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (!string.Equals(row.Version, version, StringComparison.Ordinal)
                || !IsSha256Hex(row.ContentHash)
                || !row.Filename.EndsWith(".zip", StringComparison.Ordinal))
            {
                continue;
            }

            // cache_artifact is a GLOBAL plane row (no org_id); its content_hash and blob_key
            // belong to whichever tenant fetched the coordinate first. Publishing that hash as
            // this org's zh: would let one tenant dictate the integrity anchor another tenant
            // advertises — and a chained edge takes zh: as its only fetch-time checksum, so a
            // mismatched anchor denies the provider to every downstream. Emit only when the row's
            // blob_key is THIS org's own key, proving the hash describes bytes this org holds. In
            // single-tenant deployments every row is this org's, so nothing is suppressed; in
            // multi-tenant a foreign row falls through to the upstream-published hash (or none),
            // the safe posture for an optional field.
            string platform = row.Filename[..^".zip".Length];
            string ownKey = BlobKeys.Terraform(
                orgId, provider.Hostname, provider.Namespace, provider.Type, version, platform);
            if (string.Equals(row.BlobKey, ownKey, StringComparison.Ordinal))
            {
                hashes[row.Filename] = row.ContentHash;
            }
        }

        return hashes;
    }

    /// <summary>
    /// Serves a provider archive, filling the cache on a miss. The upstream registry is asked for
    /// this exact platform's <c>download_url</c> and <c>shasum</c>; the archive is then fetched
    /// from that URL and verified against that checksum before it is stored.
    /// </summary>
    private async Task<IActionResult> ServeArchiveAsync(
        string orgId, ProviderAddress provider, string version, string platform,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        string blobKey = BlobKeys.Terraform(
            orgId, provider.Hostname, provider.Namespace, provider.Type, version, platform);

        string providerName = ProviderName(provider);
        string filename = $"{platform}.zip";
        var coordinate = new TerraformArchiveCoordinate(orgId, providerName, version, platform, filename, blobKey);

        var cacheHit = await TryServeCachedArchiveAsync(coordinate, settings, token, ct);
        if (cacheHit is not null)
        {
            return cacheHit;
        }

        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return NotFound();
        }

        int underscore = platform.IndexOf('_', StringComparison.Ordinal);
        string os = platform[..underscore];
        string arch = platform[(underscore + 1)..];

        var upstream = await ResolveUpstreamAsync(orgId, provider, ct);
        if (upstream is null)
        {
            return NotFound();
        }

        var downloadResult = await FetchUpstreamDownloadAsync(upstream.Value, provider, version, os, arch, ct);
        var download = downloadResult.Value;
        if (download?.DownloadUrl is null)
        {
            return UpstreamFailure(downloadResult.Outcome);
        }

        var (checksum, checksumRefusal) = ValidateArchiveChecksum(upstream.Value, download, providerName, version, platform);
        if (checksumRefusal is not null)
        {
            return checksumRefusal;
        }

        string purl = PurlNormalizer.Terraform(
            provider.Hostname, provider.Namespace, provider.Type, version);

        // Hash-and-stage to the blob store, then run the shared proxy pipeline against the result.
        // The streaming variant would serve the bytes straight through and leave no SHA-256 to
        // record or gate on.
        //
        // The credential is attached only when the archive lives on the configured upstream's own
        // authority — true on the mirror path, where containment already constrained it there, and
        // for a registry that serves its own archives. A registry-protocol download_url pointing
        // anywhere else names a host the upstream chose, and the org's credential does not go to it.
        var (fetchedResult, fetchError) = await FetchTerraformArchiveAsync(
            coordinate, download.DownloadUrl, checksum, purl, upstream.Value, ct);
        if (fetchError is not null)
        {
            return fetchError;
        }

        var fetched = fetchedResult!;
        var blob = new BlobHandle(fetched.BlobKey, fetched.Sha256Hex, fetched.SizeBytes,
            async openCt => await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetched.BlobKey), openCt)
                ?? throw new InvalidOperationException(
                    $"Blob {fetched.BlobKey} vanished between fetch and serve."));

        // The upstream publish timestamp, so the release-age cooldown (min_release_age_hours) can
        // fire on this fetch and on every later serve — the cache-plane row persists it. Registry
        // protocol only; a chained mirror reports null and the cooldown fails open, which is correct
        // because the master enforces its own cooldown on the real upstream fetch.
        var publishedAt =
            await FetchUpstreamPublishedAtAsync(upstream.Value, provider, version, ct);

        // The publisher-signed SHASUMS chain, when the tenant has Terraform signature
        // verification enabled and this org has at least one Terraform PGP trust anchor
        // configured. Registry-protocol only — a chained mirror carries no shasums_url/
        // shasums_signature_url, so its downstream tenant's own policy governs there instead.
        string? terraformVerifyMode = settings?.VerifyTerraformSignatures;
        (string? terraformProvenanceStatus, string? terraformProvenanceSigner) =
            await VerifyTerraformSignatureAsync(
                orgId, terraformVerifyMode, upstream.Value, download, fetched.Sha256Hex, ct);

        // The shared record -> scan -> gate sequence: source-pin the provider to its first serving
        // registry, write the cache_artifact row, scan OSV, and evaluate the block gate before any
        // byte reaches the client. Without this a vulnerable or operator-blocked provider would be
        // refused only on a later download, never on the fetch that introduced it.
        BlockDecision decision;
        try
        {
            decision = (await _svc.ProxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: orgId, Ecosystem: Ecosystem,
            PackageName: providerName, PurlName: providerName,
            Version: version, Purl: purl, File: filename, Blob: blob,
            // Provider archives carry no licence manifest — no LICENSE metadata file is mandated
            // by the protocol and the registry does not report one — so there is nothing to
            // extract. Under license_enforcement_mode=block terraform is correspondingly absent
            // from BlockGateService.DeclaredLicenseEcosystems: recording zero licences here is the
            // normal case, not an unknown-licence signal.
            ExtractLicenses: null,
            UserId: token?.UserId,
            ActorKind: token?.ActorKind,
            SourceIp: HttpContext.GetNormalizedRemoteIp(),
            MaxOsvScoreTolerance: settings?.MaxOsvScoreTolerance ?? DefaultMaxOsvScoreTolerance,
            // The cache-plane row keeps the archive's own URL, which is the audit-useful fact:
            // which host actually served these bytes.
            CacheAccess: new CacheAccess(orgId, Ecosystem, providerName, version, filename,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: download.DownloadUrl),
            PublishedAt: publishedAt,
            MinReleaseAgeHours: settings?.MinReleaseAgeHours,
            BlockDeprecatedMode: settings?.BlockDeprecated,
            BlockMaliciousMode: settings?.BlockMalicious,
            BlockKevMode: settings?.BlockKev,
            BlockRevokedMode: settings?.BlockRevoked,
            MaxEpssTolerance: settings?.MaxEpssTolerance,
            // The upstream-supplied digest re-verified at the trust boundary: the registry
            // protocol's per-platform shasum, or a chained mirror's zh: hash. Null when the upstream
            // published neither, in which case the recorded SHA-256 is an observed fact rather than
            // a check.
            UpstreamChecksum: checksum,
            // Source pinning binds the provider to the REGISTRY authority that resolved it, not to
            // the archive host. A registry-protocol download_url points at a shared release CDN
            // (releases.hashicorp.com serves every HashiCorp provider), so pinning on it would bind
            // unrelated providers to one authority — no dependency-confusion signal, and a false
            // block the day a legitimate registry rotates its release host. The registry that
            // answered is the authority a provider's source address actually names. On the mirror
            // path the base is already that authority.
            UpstreamUrl: upstream.Value.BaseUrl,
            LicenseEnforcementMode: settings?.LicenseEnforcementMode,
            ProvenanceStatus: terraformProvenanceStatus,
            ProvenanceSigner: terraformProvenanceSigner,
            VerifyProvenanceMode: terraformVerifyMode), ct)).Decision;
        }
        catch (ProxyCatalogueUnavailableException)
        {
            // The archive could not be recorded on the cache plane, so it could not be gated. The
            // blob is already staged under the org-scoped coordinate key; leaving it there would
            // answer every later request from the cache with no cache_artifact row to gate against
            // — a permanent bypass, not a deferred one. Discard it so the next request re-fetches
            // and re-gates. 503, never 404: the provider exists upstream, we just could not admit it.
            await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
            _svc.Logger.LogWarning(
                "Cache plane unavailable recording terraform {Provider} {Version} {Platform} for org "
                + "{OrgId}; refusing the fetch.", providerName, version, platform, orgId);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "Provider archive could not be recorded on the cache plane; retry.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Any other failure recording or scanning the fetch leaves the staged blob with no
            // cache_artifact row to gate against — the same permanent bypass the Blocked path
            // guards, since the Terraform cache-hit lookup probes the blob store by coordinate.
            // Discard the blob, then let the exception surface to its dedicated middleware.
            await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
            throw;
        }

        if (decision == BlockDecision.Blocked)
        {
            // Discard the staged blob along with the refusal — the load-bearing half. The Terraform
            // cache-hit lookup probes the blob store by org-scoped coordinate, and
            // IsArchiveBlockedAsync allows a hit it has no cache_artifact row for; a source-pin or
            // first-fetch gate refuses BEFORE any row is written. A staged-but-unrecorded blob would
            // therefore serve ungated on every later request — a permanent bypass rather than a
            // deferred one. The blob key is org-scoped, so discarding it affects no other tenant.
            // Same reasoning as ApkController / GoController / CargoController.
            await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        var body = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
        if (body is null)
        {
            return NotFound();
        }

        Response.Headers["X-Cache"] = "MISS";
        return File(body, "application/zip");
    }

    /// <summary>
    /// Verifies the publisher-signed SHASUMS chain for a freshly-fetched provider archive when
    /// the tenant has Terraform signature verification enabled and this org has at least one
    /// Terraform PGP trust anchor configured. Registry-protocol only: <c>shasums_url</c>/
    /// <c>shasums_signature_url</c> have no analog in the network mirror protocol, so a chained
    /// edge reports (null, null) and the downstream tenant's own policy governs there instead.
    /// Returns (null, null) when verification is off, no anchor is configured, or the mirror path
    /// is in play — leaving the provenance status column unset with no gate effect.
    /// </summary>
    private async Task<(string? Status, string? Signer)> VerifyTerraformSignatureAsync(
        string orgId, string? verifyMode, ResolvedUpstream upstream, UpstreamDownload download,
        string archiveSha256Hex, CancellationToken ct)
    {
        if (verifyMode is null or "off" || upstream.IsMirror
            || !await _svc.TerraformProvenance.IsConfiguredForAsync(orgId, ct))
        {
            return (null, null);
        }

        byte[]? shasums = string.IsNullOrWhiteSpace(download.ShasumsUrl)
            ? null
            : await TryFetchRawAsync(upstream, download.ShasumsUrl, ct);
        byte[]? signature = string.IsNullOrWhiteSpace(download.ShasumsSignatureUrl)
            ? null
            : await TryFetchRawAsync(upstream, download.ShasumsSignatureUrl, ct);

        string filename = !string.IsNullOrWhiteSpace(download.Filename)
            ? download.Filename
            : ArchiveFilenameFromUrl(download.DownloadUrl);

        var provResult = await _svc.TerraformProvenance.VerifyArchiveAsync(
            orgId, filename, archiveSha256Hex, shasums, signature, ct);
        return (ProvenanceStatuses.ToColumn(provResult.Status), provResult.Signer);
    }

    // Derives the SHASUMS filename from a download_url when the registry's download response
    // omits the "filename" field (the registry protocol names it as optional).
    private static string ArchiveFilenameFromUrl(string? url) =>
        url is not null && Uri.TryCreate(url, UriKind.Absolute, out var uri)
            ? System.IO.Path.GetFileName(uri.AbsolutePath)
            : "";

    /// <summary>
    /// Best-effort fetch of a raw upstream document (SHASUMS / SHASUMS.sig) for Terraform
    /// provenance verification. Returns null on any failure — an unreachable or malformed
    /// signature source resolves to <see cref="ProvenanceStatus.Unsigned"/>, not a
    /// serve-path fault, the same posture a missing Maven <c>.asc</c> sidecar takes. Routed
    /// through <see cref="UpstreamClient.GetOrFetchMetadataAsync(string,string?,CancellationToken)"/>
    /// like every other document read here, so a version whose platforms share one SHASUMS URL
    /// pays for the fetch once.
    /// </summary>
    private async Task<byte[]?> TryFetchRawAsync(ResolvedUpstream upstream, string url, CancellationToken ct)
    {
        try
        {
            string? authorization = AuthorizationHeaderFor(upstream, url);
            var response = await _svc.Upstream.GetOrFetchMetadataAsync(url, authorization, ct);
            return response.IsSuccessStatusCode ? response.Body : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not AirGappedException)
        {
            _svc.Logger.LogWarning(
                ex, "Terraform SHASUMS fetch from {Url} failed: {ExceptionType}", url, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// A resolved provider-archive identity, threaded unchanged through
    /// <see cref="ServeArchiveAsync"/>'s cache-hit and upstream-fetch helpers so the parameter
    /// list at each call site is the coordinate, not its six constituent fields.
    /// </summary>
    private readonly record struct TerraformArchiveCoordinate(
        string OrgId, string ProviderName, string Version, string Platform, string Filename, string BlobKey);

    /// <summary>
    /// The cache-hit path for <see cref="ServeArchiveAsync"/>: serves the already-staged archive
    /// when present. The block gate runs on every hit (not only first fetch), so an operator
    /// block or an OSV finding recorded after the archive was cached stops it serving on every
    /// subsequent download. Returns null on a cache miss so the caller falls through to the
    /// upstream fetch.
    /// </summary>
    private async Task<IActionResult?> TryServeCachedArchiveAsync(
        TerraformArchiveCoordinate coordinate, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        var (orgId, providerName, version, _, filename, blobKey) = coordinate;
        var cached = await _svc.Blobs.GetAsync(blobKey, ct);
        if (cached is null)
        {
            return null;
        }

        var facts = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, Ecosystem, providerName, version, filename, ct);

        // Dispose the opened blob stream on the refusal — on an S3/Azure backend it is a live HTTP
        // response, and a client retry loop against a blocked provider would otherwise strand one
        // per request until the pool is drained.
        if (await IsArchiveBlockedAsync(orgId, facts, settings, token, ct))
        {
            await cached.DisposeAsync();
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // Record the access on the hit too. Download counts, last_accessed_at (which drives LRU
        // eviction, so a hot provider that only ever hits looks cold), and the "which tenants
        // hold this artefact" query used during vulnerability response all read this row.
        await RecordCacheHitAsync(orgId, providerName, version, filename, blobKey, facts, ct);

        Response.Headers["X-Cache"] = "HIT";
        return File(cached, "application/zip");
    }

    /// <summary>
    /// Registry protocol: the download_url names a host the UPSTREAM chose
    /// (releases.hashicorp.com for HashiCorp's providers), and the shasum is the only thing
    /// binding those third-party bytes to the registry that vouched for them. A registry that
    /// returns no shasum for an archive on a foreign authority leaves nothing to verify — refuse
    /// rather than store trust-on-first-use bytes fetched from a host the operator never
    /// configured. The mirror protocol's hash-less TOFU is a deliberate, documented exception
    /// (ADR 0003) because a mirror serves its own bytes from beneath the configured base; this
    /// guard is registry-only.
    /// </summary>
    private (ChecksumSpec? Checksum, IActionResult? Refusal) ValidateArchiveChecksum(
        ResolvedUpstream upstream, UpstreamDownload download, string providerName, string version, string platform)
    {
        var checksum = string.IsNullOrWhiteSpace(download.Shasum)
            ? null
            : new ChecksumSpec(ChecksumAlgorithm.Sha256, download.Shasum);

        if (!upstream.IsMirror
            && checksum is null
            && !IsSameAuthority(upstream.BaseUrl, download.DownloadUrl!))
        {
            _svc.Logger.LogWarning(
                "Terraform registry {Base} returned no shasum for {Provider} {Version} {Platform} "
                + "on a third-party archive host; refusing.",
                upstream.BaseUrl, providerName, version, platform);
            return (null, StatusCode(StatusCodes.Status502BadGateway,
                "Upstream Terraform registry supplied no checksum for an archive on a third-party host."));
        }

        return (checksum, null);
    }

    /// <summary>
    /// Hash-and-stages the archive to the blob store (the streaming variant would serve the bytes
    /// straight through and leave no SHA-256 to record or gate on). The credential is attached
    /// only when the archive lives on the configured upstream's own authority — true on the
    /// mirror path, where containment already constrained it there, and for a registry that
    /// serves its own archives. A registry-protocol download_url pointing anywhere else names a
    /// host the upstream chose, and the org's credential does not go to it.
    /// </summary>
    private async Task<(UpstreamFetchResult? Fetched, IActionResult? Error)> FetchTerraformArchiveAsync(
        TerraformArchiveCoordinate coordinate, string downloadUrl, ChecksumSpec? checksum, string purl,
        ResolvedUpstream upstream, CancellationToken ct)
    {
        var (orgId, providerName, version, platform, _, blobKey) = coordinate;

        // On the mirror path the archive URL was resolved beneath the configured base; pin every
        // redirect hop of the fetch to that base too, so a mirror cannot escape it with a 302 the way
        // the URL check alone would allow. The registry protocol legitimately redirects to a release
        // host the upstream chose (releases.hashicorp.com), so it passes no containment base.
        string? containmentBase = upstream.IsMirror ? upstream.BaseUrl : null;

        try
        {
            var fetched = await _svc.Upstream.GetOrFetchToBlobKeyAsync(
                blobKey, downloadUrl, checksum, Ecosystem, orgId, purl,
                authorizationHeader: AuthorizationHeaderFor(upstream, downloadUrl),
                containmentBase: containmentBase, ct: ct);
            return (fetched, null);
        }
        catch (ChecksumException)
        {
            // The most security-significant outcome on this path: the archive host served bytes
            // that do not match the digest the registry vouched for. UpstreamClient discards the
            // staged file before throwing, so nothing entered the blob store. 502 — matching every
            // peer proxy — never an opaque 500.
            _svc.Logger.LogWarning(
                "Checksum mismatch fetching terraform {Provider} {Version} {Platform}.",
                providerName, version, platform);
            return (null, StatusCode(StatusCodes.Status502BadGateway, "Upstream checksum verification failed."));
        }
        catch (Exception ex) when (ex is SsrfBlockedException or UpstreamResponseTooLargeException)
        {
            _svc.Logger.LogWarning(
                ex, "Terraform archive fetch for {Provider} {Version} refused: {ExceptionType}",
                providerName, version, ex.GetType().Name);
            return (null, StatusCode(StatusCodes.Status502BadGateway, "Upstream Terraform archive fetch refused."));
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            _svc.Logger.LogWarning(
                ex, "Terraform archive fetch for {Provider} {Version} failed: {ExceptionType}",
                providerName, version, ex.GetType().Name);
            return (null, StatusCode(
                StatusCodes.Status503ServiceUnavailable, "Upstream Terraform archive host is unavailable."));
        }
    }

    /// <summary>
    /// The provider's canonical name for block-gate, reserved-namespace, and cache-artifact
    /// coordinates: the fully-qualified source address. Namespace/type alone is not an identity —
    /// two registry hosts may publish the same pair and they are different providers.
    /// </summary>
    internal static string ProviderName(ProviderAddress provider) =>
        $"{provider.Hostname}/{provider.Namespace}/{provider.Type}";

    private async Task<bool> IsArchiveBlockedAsync(
        string orgId, CacheArtifactServeFacts? facts,
        OrgSettings? settings, TokenRecord? token, CancellationToken ct) =>
        facts is not null
        && await _svc.BlockGate.EvaluateAsync(
            BlockGateRequest.ForProxyCacheFacts(
                orgId, Ecosystem, facts, token, settings, HttpContext.GetNormalizedRemoteIp()), ct)
            == BlockDecision.Blocked;

    /// <summary>
    /// Records a cache-hit access tick against the global cache plane, matching the apk and Go
    /// serve paths. Best-effort: an artefact with no plane row yet (fetched before the plane
    /// recorded it, or evicted from the plane but not the blob store) gets a row seeded from the
    /// blob it is about to serve rather than the tick being dropped.
    /// </summary>
    private async Task RecordCacheHitAsync(
        string orgId, string providerName, string version, string filename, string blobKey,
        CacheArtifactServeFacts? facts, CancellationToken ct)
    {
        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, Ecosystem, providerName, version, filename,
                facts?.ContentHash ?? "", facts?.SizeBytes ?? 0, blobKey, UpstreamUrl: null), ct);
        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.RecordDownloadHitAsync(
                orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);
        }
    }

    // ── Upstream resolution ──────────────────────────────────────────────────

    /// <summary>
    /// A resolved upstream: its base URL, which protocol it speaks, and the pre-built
    /// <c>Authorization</c> header value the resolver decrypted for it (null when anonymous).
    /// Carrying the credential here is what makes a chained edge — whose master is authenticated by
    /// default — able to read its master at all; dropping it turns every fetch into an anonymous one.
    /// </summary>
    private readonly record struct ResolvedUpstream(
        string BaseUrl, bool IsMirror, string? AuthorizationHeader);

    /// <summary>
    /// The credential to present when requesting <paramref name="url"/> from
    /// <paramref name="upstream"/>, or null when the URL is not on the upstream's own authority.
    ///
    /// The registry protocol hands back a <c>download_url</c> on a host the upstream chose — for
    /// HashiCorp's providers <c>releases.hashicorp.com</c>, which is not the operator's registry and
    /// not a party the org's credential belongs to. Scoping the header to the configured authority
    /// keeps a discovered third-party host from being handed a secret, while a registry that serves
    /// its own archives (and every mirror, whose archive URLs are already constrained beneath the
    /// base) still gets it.
    /// </summary>
    private static string? AuthorizationHeaderFor(ResolvedUpstream upstream, string url) =>
        upstream.AuthorizationHeader is not null && IsSameAuthority(upstream.BaseUrl, url)
            ? upstream.AuthorizationHeader
            : null;

    /// <summary>
    /// True when <paramref name="url"/> sits on the same scheme+host+port authority as
    /// <paramref name="baseUrl"/>. Both the credential-scoping decision and the registry
    /// no-checksum guard turn on "is this URL on the configured upstream's own authority", so they
    /// share one comparison rather than drifting apart.
    /// </summary>
    private static bool IsSameAuthority(string baseUrl, string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var target)
        && Uri.TryCreate(baseUrl, UriKind.Absolute, out var b)
        && string.Equals(target.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(target.Host, b.Host, StringComparison.OrdinalIgnoreCase)
        && target.Port == b.Port;

    /// <summary>
    /// Resolves which configured upstream serves this provider, walking the org's list in priority
    /// order. The two protocols admit providers on different grounds, and the difference is a
    /// security property rather than a convenience:
    ///
    /// <para>A <b>registry</b> upstream is admitted only when its host equals the provider's own
    /// registry hostname. The mirror is addressed by the provider's source address, so the request
    /// path necessarily carries a hostname the client chose; building the fetch URL from it would
    /// let any caller steer a server-side request at an arbitrary host. Matching against the
    /// configured list means an unconfigured host is simply not mirrored.</para>
    ///
    /// <para>A <b>mirror</b> upstream serves any provider, because the hostname never becomes part
    /// of a host there — it is a path segment beneath the configured base
    /// (<c>{base}/{hostname}/{ns}/{type}/…</c>), already validated as path-safe. The upstream
    /// mirror applies its own admission, which is the correct layering for a chained node: the
    /// master stays authoritative over what it will serve, exactly as it is for every other
    /// ecosystem an edge chains.</para>
    /// </summary>
    private async Task<ResolvedUpstream?> ResolveUpstreamAsync(
        string orgId, ProviderAddress provider, CancellationToken ct)
    {
        var sources = await _svc.Registries.ResolveAsync(orgId, Ecosystem, ct);
        foreach (var source in sources)
        {
            if (source.Protocol == UpstreamRegistryRepository.MirrorProtocol)
            {
                return new ResolvedUpstream(
                    source.Url.TrimEnd('/'), IsMirror: true, source.AuthorizationHeader);
            }

            if (Uri.TryCreate(source.Url, UriKind.Absolute, out var uri)
                && string.Equals(uri.Host, provider.Hostname, StringComparison.OrdinalIgnoreCase))
            {
                return new ResolvedUpstream(
                    source.Url.TrimEnd('/'), IsMirror: false, source.AuthorizationHeader);
            }
        }

        return null;
    }

    /// <summary>The provider's path beneath a mirror base: <c>{hostname}/{namespace}/{type}</c>.</summary>
    private static string MirrorPath(ProviderAddress provider) =>
        $"{provider.Hostname}/{provider.Namespace}/{provider.Type}";

    // ── Upstream fetches ─────────────────────────────────────────────────────

    /// <summary>
    /// The versions this upstream advertises. The registry protocol returns versions and their
    /// platforms in one document; the mirror protocol's index carries version strings only, so the
    /// platform list for a given version comes from <see cref="FetchUpstreamPlatformsAsync"/>
    /// instead. Callers that need only version strings can use either.
    /// </summary>
    private async Task<UpstreamResult<List<UpstreamVersion>>> FetchUpstreamVersionsAsync(
        string orgId, ProviderAddress provider, OrgSettings? settings, CancellationToken ct)
    {
        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return UpstreamResult<List<UpstreamVersion>>.Absent;
        }

        var upstream = await ResolveUpstreamAsync(orgId, provider, ct);
        if (upstream is null)
        {
            return UpstreamResult<List<UpstreamVersion>>.Absent;
        }

        if (upstream.Value.IsMirror)
        {
            var index = await GetJsonAsync<MirrorIndex>(
                upstream.Value, $"{upstream.Value.BaseUrl}/{MirrorPath(provider)}/index.json", ct);
            return index.Map(i => i.Versions?.Keys
                .Select(v => new UpstreamVersion(v, Platforms: null))
                .ToList());
        }

        string url = $"{upstream.Value.BaseUrl}/v1/providers/{provider.Namespace}/{provider.Type}/versions";
        var parsed = await GetJsonAsync<UpstreamVersions>(upstream.Value, url, ct);
        return parsed.Map(p => p.Versions);
    }

    /// <summary>
    /// The platforms this upstream advertises for one version. Split from the version list because
    /// the two protocols carry it in different documents: the registry protocol embeds it in the
    /// versions list, the mirror protocol keys it by platform in the per-version document — where
    /// each platform may also carry the hashes this controller re-emits downstream.
    /// </summary>
    private async Task<UpstreamResult<List<PlatformArchive>>> FetchUpstreamPlatformsAsync(
        string orgId, ProviderAddress provider, string version, OrgSettings? settings,
        CancellationToken ct)
    {
        if (settings is not null && !settings.ProxyPassthroughEffective)
        {
            return UpstreamResult<List<PlatformArchive>>.Absent;
        }

        var upstream = await ResolveUpstreamAsync(orgId, provider, ct);
        if (upstream is null)
        {
            return UpstreamResult<List<PlatformArchive>>.Absent;
        }

        if (!upstream.Value.IsMirror)
        {
            var versions = await FetchUpstreamVersionsAsync(orgId, provider, settings, ct);
            return versions.Map(list => list
                .Find(v => string.Equals(v.Version, version, StringComparison.Ordinal))
                ?.Platforms
                ?.Where(p => !string.IsNullOrWhiteSpace(p.Os) && !string.IsNullOrWhiteSpace(p.Arch))
                .Select(p => new PlatformArchive(p.Os!, p.Arch!, UpstreamHashes: null))
                .ToList());
        }

        var document = await GetJsonAsync<MirrorVersionDocument>(
            upstream.Value, MirrorVersionDocumentUrl(upstream.Value, provider, version), ct);
        return document.Map(d =>
        {
            if (d.Archives is null)
            {
                return null;
            }

            var platforms = new List<PlatformArchive>();
            foreach (var (key, archive) in d.Archives)
            {
                int underscore = key.IndexOf('_', StringComparison.Ordinal);
                if (underscore > 0 && underscore < key.Length - 1)
                {
                    platforms.Add(new PlatformArchive(
                        key[..underscore], key[(underscore + 1)..], archive.Hashes));
                }
            }

            return platforms;
        });
    }

    /// <summary>
    /// Where to fetch one platform's archive from, and the checksum to verify it against when the
    /// upstream supplies one. The registry protocol names an arbitrary release host and a
    /// <c>shasum</c>; the mirror protocol names a URL relative to its own version document, and its
    /// hashes are the lock-file forms, of which <c>zh:</c> is the archive's SHA-256.
    /// </summary>
    private async Task<UpstreamResult<UpstreamDownload>> FetchUpstreamDownloadAsync(
        ResolvedUpstream upstream, ProviderAddress provider, string version, string os, string arch,
        CancellationToken ct)
    {
        if (!upstream.IsMirror)
        {
            string url =
                $"{upstream.BaseUrl}/v1/providers/{provider.Namespace}/{provider.Type}/{version}/download/{os}/{arch}";
            return await GetJsonAsync<UpstreamDownload>(upstream, url, ct);
        }

        string documentUrl = MirrorVersionDocumentUrl(upstream, provider, version);
        var result = await GetJsonAsync<MirrorVersionDocument>(upstream, documentUrl, ct);
        var document = result.Value;
        if (document?.Archives is null
            || !document.Archives.TryGetValue($"{os}_{arch}", out var archive)
            || string.IsNullOrWhiteSpace(archive.Url))
        {
            return document is null
                ? UpstreamResult<UpstreamDownload>.From(result.Outcome)
                : UpstreamResult<UpstreamDownload>.Absent;
        }

        // Archive URLs are relative to the version document. Resolving them against the document and
        // requiring the result to stay beneath the configured base keeps a hostile or compromised
        // mirror from pointing the fetch at a host of its choosing: unlike the registry protocol —
        // where an arbitrary release host is the design — a mirror serves its own archives, so
        // anything pointing elsewhere is not a shape worth honouring. This check covers the published
        // URL; the redirect hops of the fetch are pinned to the same base by the containmentBase
        // passed to GetOrFetchToBlobKeyAsync in ServeArchiveAsync, so a compliant URL cannot 302 off
        // it either.
        if (!Uri.TryCreate(new Uri(documentUrl), archive.Url, out var resolved)
            || !IsBeneathBase(resolved, upstream.BaseUrl))
        {
            _svc.Logger.LogWarning(
                "Terraform mirror {Base} offered an archive URL outside its own base for {Provider} {Version} {Os}_{Arch}; refusing.",
                upstream.BaseUrl, MirrorPath(provider), version, os, arch);
            return UpstreamResult<UpstreamDownload>.From(UpstreamOutcome.BadGateway);
        }

        return UpstreamResult<UpstreamDownload>.Ok(
            new UpstreamDownload(resolved.ToString(), ExtractZipHash(archive.Hashes)));
    }

    /// <summary>
    /// The upstream publish timestamp for a provider version, feeding the release-age cooldown gate
    /// (<c>min_release_age_hours</c>). Registry-protocol only: it comes from the per-version
    /// metadata document, which the network mirror protocol has no equivalent for — a chained edge
    /// therefore reports null and the cooldown fails open there, which is correct because the master
    /// enforces its own cooldown on the real upstream fetch.
    ///
    /// Best-effort: a missing endpoint, an unparseable timestamp, or any upstream fault yields null
    /// rather than failing the archive fetch. That is the same fail-open-on-a-missing-signal posture
    /// <see cref="BlockGateService"/> already takes for a null publish timestamp, so a registry that
    /// does not serve this document simply leaves the cooldown inert rather than blocking a fetch.
    /// The read goes through <see cref="GetJsonAsync{T}"/>, so it is single-flighted and TTL-cached
    /// — the platforms of one version share one metadata fetch.
    /// </summary>
    private async Task<DateTimeOffset?> FetchUpstreamPublishedAtAsync(
        ResolvedUpstream upstream, ProviderAddress provider, string version, CancellationToken ct)
    {
        if (upstream.IsMirror)
        {
            return null;
        }

        string url = $"{upstream.BaseUrl}/v1/providers/{provider.Namespace}/{provider.Type}/{version}";
        var result = await GetJsonAsync<UpstreamVersionMetadata>(upstream, url, ct);
        return DateTimeOffset.TryParse(
            result.Value?.PublishedAt, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : null;
    }

    private static string MirrorVersionDocumentUrl(
        ResolvedUpstream upstream, ProviderAddress provider, string version) =>
        $"{upstream.BaseUrl}/{MirrorPath(provider)}/{version}.json";

    /// <summary>
    /// True when <paramref name="candidate"/> sits beneath <paramref name="baseUrl"/>. The check
    /// itself lives in <see cref="UriContainment.IsBeneath"/> so the same definition governs both a
    /// mirror's published archive URL (here) and every redirect target the fetch follows
    /// (<see cref="SsrfAwareRedirectHandler"/>) — a mirror cannot escape its base by redirect any
    /// more than by the URL it publishes.
    /// </summary>
    internal static bool IsBeneathBase(Uri candidate, string baseUrl) =>
        UriContainment.IsBeneath(candidate, baseUrl);

    /// <summary>
    /// The <c>zh:</c> entry of a mirror's hash list, which is the archive's SHA-256 in hex and so
    /// the one form usable as a fetch-time checksum. <c>h1:</c> is Terraform's dirhash over the
    /// extracted contents — a different computation the fetch path cannot verify. Null when the
    /// mirror published neither, which is the documented normal case rather than a fault: the
    /// archive is still hashed and recorded on ingest.
    ///
    /// A <c>zh:</c> entry whose value is not a well-formed SHA-256 (a bare <c>zh:</c>, or any
    /// non-64-hex string) is treated as absent rather than fed to the verifier as a checksum: an
    /// empty value would silently downgrade to trust-on-first-use, and a malformed one would fail
    /// closed as an opaque error. Either way "the mirror published a hash" and "the mirror
    /// published a usable hash" must not be indistinguishable, so the unusable form is dropped.
    /// </summary>
    internal static string? ExtractZipHash(List<string>? hashes)
    {
        string? value = hashes?.Find(h => h.StartsWith("zh:", StringComparison.Ordinal))?["zh:".Length..];
        return IsSha256Hex(value) ? value : null;
    }

    /// <summary>True when <paramref name="value"/> is exactly 64 lowercase-or-uppercase hex digits.</summary>
    private static bool IsSha256Hex([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    // ── Upstream document reads ──────────────────────────────────────────────

    /// <summary>
    /// How an upstream document read ended. The distinction is the whole point: collapsing
    /// everything into "no document" makes an auth refusal and an upstream outage both read as
    /// "provider not found", which is the answer a client acts on by giving up.
    /// </summary>
    private enum UpstreamOutcome
    {
        /// <summary>The document was read and parsed.</summary>
        Ok,

        /// <summary>
        /// Nothing to serve, and nothing wrong: no upstream is configured for this provider,
        /// passthrough is off, or the upstream answered 404. Callers answer 404, which is what the
        /// network mirror protocol expects for a provider a mirror does not cover.
        /// </summary>
        Absent,

        /// <summary>
        /// A deterministic verdict this instance cannot work around: the upstream refused the
        /// credential presented, demanded one that is not configured, or answered with something
        /// unusable. Callers answer 502 — retrying changes nothing, an operator must act.
        /// </summary>
        BadGateway,

        /// <summary>
        /// A transient failure: the upstream was unreachable, timed out, answered 5xx, or refused
        /// an anonymous request the way a public CDN's bot mitigation does. Callers answer 503,
        /// which tells the client to retry rather than that the provider does not exist.
        /// </summary>
        Unavailable,
    }

    /// <summary>An upstream document read: its outcome, and the parsed document when it succeeded.</summary>
    private readonly record struct UpstreamResult<T>(UpstreamOutcome Outcome, T? Value)
        where T : class
    {
        public static UpstreamResult<T> Ok(T value) => new(UpstreamOutcome.Ok, value);

        public static UpstreamResult<T> Absent => new(UpstreamOutcome.Absent, null);

        public static UpstreamResult<T> From(UpstreamOutcome outcome) => new(outcome, null);

        /// <summary>
        /// Projects a successfully-read document into another shape, preserving the failure
        /// outcome. A projection that yields null degrades to <see cref="UpstreamOutcome.Absent"/>:
        /// the upstream answered, it simply carries nothing for this coordinate.
        /// </summary>
        public UpstreamResult<TOut> Map<TOut>(Func<T, TOut?> project) where TOut : class
        {
            if (Value is null)
            {
                return UpstreamResult<TOut>.From(Outcome);
            }

            var projected = project(Value);
            return projected is null ? UpstreamResult<TOut>.Absent : UpstreamResult<TOut>.Ok(projected);
        }
    }

    /// <summary>Maps a failed upstream read onto the response the client sees.</summary>
    private IActionResult UpstreamFailure(UpstreamOutcome outcome) => outcome switch
    {
        UpstreamOutcome.BadGateway => StatusCode(
            StatusCodes.Status502BadGateway, "Upstream Terraform registry refused the request."),
        UpstreamOutcome.Unavailable => StatusCode(
            StatusCodes.Status503ServiceUnavailable, "Upstream Terraform registry is unavailable."),
        _ => NotFound(),
    };

    /// <summary>
    /// Reads a JSON document from an upstream, through the shared <see cref="UpstreamClient"/>
    /// metadata path — which is what brings the air-gap refusal, the URL-validator pre-flight, the
    /// 32 MB body cap, single-flight dedup, and the short-TTL response cache. A raw named client
    /// has none of those, and the amplification matters here: a fleet of CI runners with no
    /// <c>.terraform</c> between jobs asks for the same index documents at once.
    ///
    /// The upstream's credential is attached only for URLs on its own authority; every caller here
    /// builds one from the configured base, and the check is belt-and-braces against a future one
    /// that does not.
    /// </summary>
    private async Task<UpstreamResult<T>> GetJsonAsync<T>(
        ResolvedUpstream upstream, string url, CancellationToken ct) where T : class
    {
        string? authorization = AuthorizationHeaderFor(upstream, url);
        UpstreamMetadataResponse response;
        try
        {
            response = await _svc.Upstream.GetOrFetchMetadataAsync(url, authorization, ct);
        }
        catch (AirGappedException)
        {
            // Air-gap is a deliberate posture, not an upstream fault: it surfaces through the
            // shared middleware so every ecosystem reports it identically.
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SsrfBlockedException
                                       or UpstreamResponseTooLargeException)
        {
            _svc.Logger.LogWarning(
                ex, "Terraform upstream request to {Url} failed: {ExceptionType}", url, ex.GetType().Name);
            return UpstreamResult<T>.From(
                ex is SsrfBlockedException or UpstreamResponseTooLargeException
                    ? UpstreamOutcome.BadGateway
                    : UpstreamOutcome.Unavailable);
        }

        if (!response.IsSuccessStatusCode)
        {
            return UpstreamResult<T>.From(ClassifyStatus(response.StatusCode, url, authorization));
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<T>(response.Body, MirrorJson);
            return parsed is null ? UpstreamResult<T>.Absent : UpstreamResult<T>.Ok(parsed);
        }
        catch (JsonException ex)
        {
            _svc.Logger.LogWarning(
                ex, "Terraform upstream at {Url} returned an unparseable document: {ExceptionType}",
                url, ex.GetType().Name);
            return UpstreamResult<T>.From(UpstreamOutcome.BadGateway);
        }
    }

    /// <summary>
    /// Applies the upstream-refusal contract to a non-success status. A 404 is a normal answer —
    /// it is how a registry reports an unknown provider, version, or platform. A 401/403 against a
    /// credential we presented is a deterministic verdict about that credential (502); an anonymous
    /// 403 is the shape public CDNs emit under bot mitigation and stays retryable (503), while an
    /// anonymous 401 says the upstream needs a credential this org has not configured, which no
    /// retry fixes.
    /// </summary>
    private UpstreamOutcome ClassifyStatus(int status, string url, string? authorization)
    {
        var outcome = status switch
        {
            StatusCodes.Status404NotFound => UpstreamOutcome.Absent,
            StatusCodes.Status401Unauthorized => UpstreamOutcome.BadGateway,
            StatusCodes.Status403Forbidden => authorization is not null
                ? UpstreamOutcome.BadGateway
                : UpstreamOutcome.Unavailable,
            _ => UpstreamOutcome.Unavailable,
        };

        if (outcome == UpstreamOutcome.Absent)
        {
            _svc.Logger.LogDebug(
                "Terraform upstream request to {Url} returned {Status}", url, status);
        }
        else
        {
            // Above Debug deliberately: an authentication or availability failure that logs at
            // Debug is what makes a broken chain look like a missing provider to an operator.
            _svc.Logger.LogWarning(
                "Terraform upstream request to {Url} returned {Status} (authenticated={Authenticated}); "
                + "answering {Outcome}.",
                url, status, authorization is not null, outcome);
        }

        return outcome;
    }
}

/// <summary>Scoped DI bundle for the Terraform provider mirror controller.</summary>
public sealed record TerraformControllerServices(
    TokenRepository Tokens,
    OrgRepository Orgs,
    IBlobStore Blobs,
    UpstreamClient Upstream,
    UpstreamRegistryResolver Registries,
    CacheAccessRecorder CacheRecorder,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    ReservedNamespaceService Reserved,
    BlockGateService BlockGate,
    ProxyFetchService ProxyFetch,
    TimeProvider Time,
    ILogger<TerraformController> Logger,
    TerraformProvenanceVerifier TerraformProvenance);
