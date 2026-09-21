using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;

namespace Dependably.Api.NpmProtocol;

/// <summary>
/// Reads the npm packument once on proxy first-fetch and turns it into the facts the tarball path
/// records: the published timestamp, the upstream integrity spec, the raw shasum, the SRI string
/// the version detail UI shows, the deprecation notice, and the registry signatures — plus the
/// provenance verdict those signatures resolve to.
///
/// <para>Separate from <see cref="NpmTarballHandler"/> because reading and verifying upstream
/// metadata is a different job from serving a tarball, and because the handler that serves the
/// tarball has no other reason to depend on the provenance verifier.</para>
/// </summary>
public sealed class NpmFirstFetchMetadataReader(
    UpstreamClient upstream,
    NpmProvenanceVerifier provenance)
{
    // Runs npm registry-signature verification for a proxy-origin version when the tenant enabled
    // it. Off-policy or an org with no trust anchors short-circuits to NotApplicable (NULL status,
    // never blocks). The signed payload is "{name}@{version}:{integrity}", so the integrity SRI
    // and the registry-published signatures both come from the packument dist node.
    internal Task<ProvenanceResult> ResolveProvenanceAsync(
        OrgSettings settings, string orgId, string fullName, string version,
        NpmFirstFetchMetadata meta, CancellationToken ct)
        => settings.VerifyNpmSignatures == "off"
            ? Task.FromResult(ProvenanceResult.NotApplicable)
            : provenance.VerifyForOrgAsync(
                orgId, new ProvenanceInput("npm", fullName, version, meta.RawIntegrity, meta.Signatures), ct);

    /// <summary>
    /// Fetches the npm packument once on proxy first-fetch and extracts everything we care
    /// about: the per-version published timestamp, an upstream integrity spec for fail-fast
    /// verification (<c>dist.integrity</c> SRI sha512 preferred, <c>dist.shasum</c> SHA-1
    /// fallback), the raw <c>dist.shasum</c> hex so the packument we re-emit later can carry
    /// the correct SHA-1, and the verbatim SRI string for the version detail UI. Fail-soft:
    /// any error returns a record full of nulls and the caller proceeds without verification
    /// or capture.
    /// </summary>
    internal async Task<NpmFirstFetchMetadata> TryFetchAsync(
        UpstreamSource upstreamSource, string fullName, string version, CancellationToken ct)
    {
        try
        {
            // Route through single-flighted metadata fetch — TryFetchAsync
            // is called inline with the tarball-fetch handler, so a stampede on the tarball
            // path otherwise drives a duplicate stampede on the packument URL too.
            var resp = await upstream.GetOrFetchMetadataAsync(
                $"{upstreamSource.Url}/{fullName}", upstreamSource.AuthorizationHeader, ct);
            if (!resp.IsSuccessStatusCode)
            {
                return NpmFirstFetchMetadata.Empty;
            }

            string json = resp.BodyAsString();
            var node = System.Text.Json.Nodes.JsonNode.Parse(json);

            DateTimeOffset? publishedAt = null;
            string? timeStr = node?["time"]?[version]?.GetValue<string>();
            if (DateTimeOffset.TryParse(timeStr, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var ts))
            {
                publishedAt = ts;
            }

            var versionNode = node?["versions"]?[version];
            var dist = versionNode?["dist"];
            string? integrity = dist?["integrity"]?.GetValue<string>();
            string? shasum = dist?["shasum"]?.GetValue<string>();
            var checksum = ChecksumVerifier.ParseNpmIntegrity(integrity, shasum);

            // Only surface the integrity string when it's actually the SHA-512 SRI form; older
            // packages might carry a non-SRI value in this field, in which case the UI label
            // ("SHA-512 SRI") would lie. Anything else stays NULL.
            string? integritySri = integrity is not null
                && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase)
                ? integrity : null;

            string? deprecated = LicenseExtractor.FromNpmPackumentVersion(versionNode).Deprecated;

            // Registry signatures over "{name}@{version}:{integrity}". The signed integrity is the
            // exact dist.integrity string (signed packages always carry the sha512 SRI form), so
            // pass it through verbatim — distinct from integritySri, which is NULLed for the UI
            // label when not SRI-shaped.
            var signatures = ParseNpmSignatures(dist?["signatures"]);

            return new NpmFirstFetchMetadata(
                publishedAt, checksum, shasum, integritySri, deprecated, integrity, signatures);
        }
        catch { return NpmFirstFetchMetadata.Empty; }
    }

    // Parses the dist.signatures array ([{ keyid, sig }, …]) into the provenance signature list.
    // Returns an empty list (never null) when the field is absent or malformed — an unsigned
    // version maps to a list with zero entries.
    private static List<ProvenanceSignature> ParseNpmSignatures(System.Text.Json.Nodes.JsonNode? signaturesNode)
    {
        if (signaturesNode is not System.Text.Json.Nodes.JsonArray arr)
        {
            return [];
        }

        var list = new List<ProvenanceSignature>(arr.Count);
        foreach (var entry in arr)
        {
            string? keyId = entry?["keyid"]?.GetValue<string>();
            string? sig = entry?["sig"]?.GetValue<string>();
            if (!string.IsNullOrEmpty(keyId) && !string.IsNullOrEmpty(sig))
            {
                list.Add(new ProvenanceSignature(keyId, sig));
            }
        }

        return list;
    }
}

internal readonly record struct NpmFirstFetchMetadata(
    DateTimeOffset? PublishedAt,
    ChecksumSpec? Checksum,
    string? Sha1Hex,
    string? IntegritySri,
    string? Deprecated,
    string? RawIntegrity,
    IReadOnlyList<ProvenanceSignature> Signatures)
{
    public static NpmFirstFetchMetadata Empty => new(null, null, null, null, null, null, []);
}
