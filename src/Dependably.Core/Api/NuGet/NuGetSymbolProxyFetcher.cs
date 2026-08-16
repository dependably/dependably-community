using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Fetches a single Portable PDB from an upstream NuGet symbol server on an SSQP miss, records it
/// on the shared cache plane, indexes it for next time, and reports the gate decision.
///
/// <para>
/// Forward-on-miss is the only shape nuget.org supports. Its service index carries
/// <c>SymbolPackagePublish</c> — push only — and no resource for downloading a <c>.snupkg</c>, so
/// there is no whole-archive to fetch alongside a proxied package; the documented consumption path
/// is SSQP by debug-id.
/// </para>
///
/// <para>
/// A debug-id carries no package identity, so the fetched PDB is recorded under its own
/// <see cref="SymbolEcosystem"/> discriminator, content-addressed by (pdb filename, SSQP key) the
/// way OCI is by digest. Keeping it out of the <c>nuget</c> ecosystem is what stops a "package"
/// named <c>mylib.pdb</c> appearing in package lists, dashboards, and SBOMs.
/// </para>
/// </summary>
public sealed class NuGetSymbolProxyFetcher(
    UpstreamRegistryRepository upstreams,
    UpstreamClient upstreamClient,
    ProxyFetchService proxyFetch,
    NuGetSymbolIndexRepository symbolIndex,
    CacheArtifactRepository cacheArtifacts,
    IBlobStore blobs,
    ILogger<NuGetSymbolProxyFetcher> logger)
{
    /// <summary>
    /// Ecosystem discriminator for proxied symbol artefacts. Deliberately distinct from
    /// <c>nuget</c>: a PDB is not a package, and cataloguing it as one would put it in every
    /// surface that enumerates NuGet packages.
    ///
    /// <para>
    /// The discriminator only keeps PDBs out of the catalogue because
    /// <see cref="CatalogueHiddenEcosystems"/> covers it — if the two ever drift, a proxied PDB
    /// starts appearing as a package named <c>mylib.pdb</c>. Asserted by
    /// <c>NuGetSymbolProxyFetcherTests.SymbolEcosystem_IsCoveredByCatalogueHiddenEcosystems</c>
    /// rather than a static-constructor guard here, so a drift fails a test run instead of
    /// permanently poisoning this type for the rest of the process the first time it is touched.
    /// </para>
    /// </summary>
    public const string SymbolEcosystem = "nuget-symbols";

    /// <summary>
    /// Attempts to fetch <paramref name="pdbName"/>/<paramref name="key"/> from each configured
    /// upstream symbol server in priority order. Returns the recorded artefact's cache id and blob
    /// key on the first success, or <see langword="null"/> when no upstream is configured, none
    /// has the PDB, or the fetch is refused.
    ///
    /// <para>
    /// Fail-closed by omission: an upstream with no <c>symbol_server_url</c> is skipped entirely
    /// rather than guessed at. Air-gap and SSRF are enforced inside
    /// <see cref="UpstreamClient.FetchAndCacheByUrlAsync"/> — an air-gapped instance throws
    /// <see cref="AirGappedException"/> before any socket is opened.
    /// </para>
    /// </summary>
    public async Task<SymbolProxyResult?> TryFetchAsync(
        SymbolProxyRequest request, CancellationToken ct)
    {
        var sources = await upstreams.ListSourcesForEcosystemAsync(request.OrgId, "nuget", ct);
        foreach (var source in sources)
        {
            if (string.IsNullOrWhiteSpace(source.SymbolServerUrl))
            {
                continue;
            }

            var result = await TryFetchFromAsync(source, request, ct);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }

    private async Task<SymbolProxyResult?> TryFetchFromAsync(
        UpstreamSource source, SymbolProxyRequest request, CancellationToken ct)
    {
        // SSQP layout: {base}/{pdbName}/{key}/{pdbName}. Both segments are already validated by
        // the route (the key by its 40-hex constraint) and are lowercased here to match how the
        // index and every SSQP client normalise them.
        string url = $"{source.SymbolServerUrl!.TrimEnd('/')}/{request.PdbName}/{request.SsqpKey}/{request.PdbName}";

        UpstreamFetchResult fetched;
        try
        {
            // Checksum spec is null: a symbol server publishes no digest for a PDB, so there is
            // nothing to verify against. The bytes are content-addressed on store regardless.
            fetched = await upstreamClient.FetchAndCacheByUrlAsync(
                url, checksumSpec: null, SymbolEcosystem, request.OrgId, ct: ct);
        }
        catch (AirGappedException)
        {
            // Air-gapped: the fallback is refused outright, not attempted against another upstream.
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or UpstreamFetchFailedException)
        {
            // This upstream does not have the PDB (or is unreachable) — try the next one. Symbol
            // misses are the common case for any package whose author published no symbols.
            logger.LogDebug(
                "Symbol server {UpstreamUrl} did not serve {PdbName}/{SsqpKey}: {ExceptionType}",
                source.Url, request.PdbName, request.SsqpKey, ex.GetType().Name);
            return null;
        }

        // BlobHandle wraps the cached bytes so ProxyFetchService can reopen a fresh stream over
        // them without the caller holding one across the record.
        var blob = new BlobHandle(fetched.BlobKey, fetched.Sha256Hex, fetched.SizeBytes,
            async openCt => await blobs.GetAsync(fetched.BlobKey, openCt) ?? Stream.Null);
        var recorded = await proxyFetch.RecordAndScanAsync(
            BuildRequest(request, blob, url), ct);

        // Index against the cache artifact so the next lookup for this debug-id is a local hit
        // rather than another upstream round trip. Best-effort, exactly as on the push path: the
        // artefact is already recorded and servable, so a failure here must not fail this request.
        var facts = await cacheArtifacts.GetServeFactsByCoordinateAsync(
            request.OrgId, SymbolEcosystem, request.PdbName, request.SsqpKey, request.PdbName, ct);
        string? cacheArtifactId = facts?.Id;
        if (cacheArtifactId is not null)
        {
            await IndexFetchedPdbAsync(request, cacheArtifactId, recorded.BlobKey, ct);
        }

        return new SymbolProxyResult(cacheArtifactId, recorded.BlobKey, recorded.Decision);
    }

    private async Task IndexFetchedPdbAsync(
        SymbolProxyRequest request, string cacheArtifactId, string blobKey, CancellationToken ct)
    {
        try
        {
            // The blob IS the PDB here — not an archive holding one — so the entry path is empty
            // and the serve path streams the blob directly.
            await symbolIndex.IndexOwnedAsync(
                request.OrgId,
                SymbolOwner.ForCacheArtifact(cacheArtifactId),
                blobKey,
                [new PdbSymbol(request.PdbName, request.SsqpKey, EntryPath: "")],
                ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Failed to index proxied symbol {PdbName}/{SsqpKey} for org {OrgId}: {ExceptionType}",
                request.PdbName, request.SsqpKey, request.OrgId, ex.GetType().Name);
        }
    }

    private static ProxyFetchRequest BuildRequest(
        SymbolProxyRequest request, BlobHandle blob, string url)
    {
        // Content-addressed coordinate: the PDB filename is the name and the debug-id is the
        // version, which is the only stable identity a debug-id lookup carries.
        string purl = $"pkg:{SymbolEcosystem}/{request.PdbName}@{request.SsqpKey}";
        return new ProxyFetchRequest(
            OrgId: request.OrgId,
            Ecosystem: SymbolEcosystem,
            PackageName: request.PdbName,
            PurlName: request.PdbName,
            Version: request.SsqpKey,
            Purl: purl,
            File: request.PdbName,
            Blob: blob,
            // A PDB declares no licence; it is debug metadata for a package whose licence is
            // recorded on the package itself.
            ExtractLicenses: null,
            AuditActorId: request.AuditActorId, AuditActorLabel: request.AuditActorLabel,
            ActorKind: request.ActorKind,
            SourceIp: request.SourceIp,
            MaxOsvScoreTolerance: request.Settings.MaxOsvScoreTolerance,
            CacheAccess: new CacheAccess(
                request.OrgId, SymbolEcosystem, request.PdbName, request.SsqpKey, request.PdbName,
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: url,
                // ProxyFetchService overwrites the three bytes fields with the values it computed
                // over the symbol package it just staged before handing this to the recorder.
                Origin: CacheAccessOrigin.FirstFetch),
            MinReleaseAgeHours: request.Settings.MinReleaseAgeHours,
            BlockMaliciousMode: request.Settings.BlockMalicious,
            BlockKevMode: request.Settings.BlockKev,
            BlockRevokedMode: request.Settings.BlockRevoked,
            MaxEpssTolerance: request.Settings.MaxEpssTolerance,
            LicenseEnforcementMode: request.Settings.LicenseEnforcementMode);
    }
}

/// <summary>Inputs for one SSQP forward-on-miss fetch.</summary>
public sealed record SymbolProxyRequest(
    string OrgId,
    string PdbName,
    string SsqpKey,
    OrgSettings Settings,
    string? AuditActorId,
    string? ActorKind,
    string? SourceIp,
    /// <summary>
    /// The actor's display name, carried alongside <see cref="AuditActorId"/> and written to
    /// <c>actor_label</c> so the row stays readable after the row it would otherwise join to
    /// is gone. Non-null for a service token only — <c>TokenRecord.AuditActorLabel</c> derives
    /// it, so no call site can put a user's email in that column. NULL means "resolve through
    /// the existing join", which is what rows predating the column already do.
    /// </summary>
    string? AuditActorLabel = null);

/// <summary>
/// Outcome of a forward-on-miss fetch: the recorded cache artefact, the stored blob, and the gate
/// decision the caller must honour before serving the bytes.
/// </summary>
public sealed record SymbolProxyResult(string? CacheArtifactId, string BlobKey, BlockDecision Decision);
