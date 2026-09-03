using Dependably.Protocol;
using Microsoft.Extensions.Logging;

namespace Dependably.Protocol.Hex;

/// <summary>How an upstream answered for one package.</summary>
public enum HexUpstreamOutcome
{
    /// <summary>A verified <c>Package</c> resource was read.</summary>
    Ok,

    /// <summary>No configured upstream lists the package (404), or none is configured or keyed.</summary>
    Absent,

    /// <summary>An upstream answered but could not be trusted or reached: non-2xx, bad signature, wrong origin, transport fault.</summary>
    Fault,
}

/// <summary>The verified upstream package and the source that served it, or the reason there is none.</summary>
public sealed record HexUpstreamPackageResult(HexPackage? Package, HexUpstreamOutcome Outcome, UpstreamSource? Source)
{
    public static readonly HexUpstreamPackageResult Absent = new(null, HexUpstreamOutcome.Absent, null);
}

/// <summary>
/// The one way this registry reads a package from a Hex upstream: the org's configured sources in
/// priority order, the signed <c>/packages/NAME</c> resource opened with the source's public key,
/// and the payload's embedded repository name checked where it is known. Shared by the read
/// plane, the latest-version resolver, the deprecation refresh and the lookup service, so every
/// consumer applies the same trust rules — an upstream with no known key is never consulted, and
/// a resource that fails verification is a fault rather than a silent empty answer. An edge node's
/// master is the one source whose key is read rather than configured (<see cref="HexMasterKeyResolver"/>);
/// it still has to have one by the time this decides, so the rule itself is unchanged.
/// </summary>
public static class HexUpstreamPackageFetcher
{
    public static async Task<HexUpstreamPackageResult> FetchAsync(
        UpstreamClient upstream, UpstreamRegistryResolver registries, string orgId, string name,
        ILogger logger, HexMasterKeyResolver? masterKeys, CancellationToken ct)
    {
        // On an edge the master's key is read from the master rather than configured on the row;
        // everywhere else — and wherever no resolver is wired — the sources pass through untouched.
        var configured = await registries.ResolveAsync(orgId, "hex", ct);
        var sources = masterKeys is null ? configured : await masterKeys.WithMasterKeyAsync(configured, ct);
        var outcome = HexUpstreamOutcome.Absent;
        foreach (var source in sources)
        {
            if (source.PublicKeyPem is null)
            {
                logger.LogWarning("Hex upstream {Url} has no public key configured; skipping it.", source.Url);
                continue;
            }

            var attempt = await TryFetchFromSourceAsync(upstream, source, name, logger, ct);
            if (attempt.Package is not null)
            {
                return attempt;
            }

            // A source that faulted is remembered so an all-404 sweep still reads as Absent while
            // any fault turns the miss into a 502 rather than a 404 the client would cache.
            if (attempt.Outcome == HexUpstreamOutcome.Fault)
            {
                outcome = HexUpstreamOutcome.Fault;
            }
        }

        return new HexUpstreamPackageResult(null, outcome, null);
    }

    /// <summary>
    /// One upstream's answer for <paramref name="name"/>: the verified package, or the outcome that
    /// decides whether the sweep continues as a miss (Absent) or as a fault. Every refusal —
    /// an unverifiable signature, a mismatched repository name, a transport failure — is a fault,
    /// never a silent miss.
    /// </summary>
    private static async Task<HexUpstreamPackageResult> TryFetchFromSourceAsync(
        UpstreamClient upstream, UpstreamSource source, string name, ILogger logger, CancellationToken ct)
    {
        string url = $"{source.Url.TrimEnd('/')}/packages/{Uri.EscapeDataString(name)}";
        try
        {
            var response = await upstream.GetOrFetchMetadataAsync(url, source.AuthorizationHeader, ct);
            if (response.StatusCode == 404)
            {
                return new HexUpstreamPackageResult(null, HexUpstreamOutcome.Absent, null);
            }

            if (!response.IsSuccessStatusCode)
            {
                return new HexUpstreamPackageResult(null, HexUpstreamOutcome.Fault, null);
            }

            using var upstreamKey = HexRegistrySigner.ParsePublicKeyPem(source.PublicKeyPem!);
            byte[] payload = HexRegistrySigner.OpenResource(response.Body, upstreamKey);
            var package = HexRegistryCodec.DecodePackage(payload);
            // The signature already binds the payload to the configured key's holder; the
            // embedded repository name is additionally checked where it is known — hex.pm's
            // is fixed — so a well-known upstream cannot hand back another repository's index.
            string? expectedRepository = HexWellKnownRepositories.RepositoryNameFor(source.Url);
            return package.Name == name && (expectedRepository is null || package.Repository == expectedRepository)
                ? new HexUpstreamPackageResult(package, HexUpstreamOutcome.Ok, source)
                : throw new HexProtocolException(
                    $"Upstream package resource names '{package.Repository}/{package.Name}', not '{expectedRepository ?? "*"}/{name}'.");
        }
        catch (HexProtocolException ex)
        {
            logger.LogWarning("Hex upstream {Url} answered an unverifiable resource for {Name}: {Detail}", source.Url, name, ex.Message);
            return new HexUpstreamPackageResult(null, HexUpstreamOutcome.Fault, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            logger.LogWarning("Hex upstream {Url} request for {Name} failed: {ExceptionType}", source.Url, name, ex.GetType().Name);
            return new HexUpstreamPackageResult(null, HexUpstreamOutcome.Fault, null);
        }
    }

    /// <summary>
    /// The releases a resolver may pick from, newest first: stable (no pre-release tag) and not
    /// retired — a retired release is Hex's deprecation and is never the "latest".
    /// </summary>
    public static IReadOnlyList<string> StableVersionsDescending(HexPackage package) =>
        EcosystemVersionOrdering.OrderStableDescending("hex",
            package.Releases.Where(r => r.Retired is null).Select(r => r.Version));
}
