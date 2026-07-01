using System.Security.Cryptography.X509Certificates;
using Dependably.Infrastructure;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Minimal <see cref="IPerOrgTrustAnchorStore"/> for use in unit test doubles and
/// ControllerScenario wiring that does not need an actual database. Returns empty / null
/// for all queries unless pre-loaded via <see cref="AddAnchor"/>.
/// </summary>
public sealed class StubPerOrgTrustAnchorStore : IPerOrgTrustAnchorStore
{
    private readonly List<(string OrgId, string Ecosystem, TrustAnchorMaterial Material)> _anchors = [];

    /// <summary>Adds a pre-seeded anchor for the given org and ecosystem.</summary>
    public void AddAnchor(string orgId, string ecosystem, TrustAnchorMaterial material)
        => _anchors.Add((orgId, ecosystem, material));

    public Task<bool> IsConfiguredForAsync(string orgId, string ecosystem, CancellationToken ct = default)
        => Task.FromResult(_anchors.Any(a =>
            a.OrgId == orgId &&
            string.Equals(a.Ecosystem, ecosystem, StringComparison.Ordinal)));

    public Task<IReadOnlyList<TrustAnchorMaterial>> ListAsync(
        string orgId, string ecosystem, CancellationToken ct = default)
    {
        IReadOnlyList<TrustAnchorMaterial> result = _anchors
            .Where(a => a.OrgId == orgId &&
                        string.Equals(a.Ecosystem, ecosystem, StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();
        return Task.FromResult(result);
    }

    public Task<PgpPublicKeyRingBundle?> GetRpmKeyRingAsync(string orgId, CancellationToken ct = default)
        => GetPgpKeyRingAsync(orgId, "rpm");

    public Task<PgpPublicKeyRingBundle?> GetMavenKeyRingAsync(string orgId, CancellationToken ct = default)
        => GetPgpKeyRingAsync(orgId, "maven");

    // Shared PGP ring builder for stub: filters by (orgId, ecosystem) and assembles via PgpKeyRingBuilder.
    private Task<PgpPublicKeyRingBundle?> GetPgpKeyRingAsync(string orgId, string ecosystem)
    {
        var anchors = _anchors
            .Where(a => a.OrgId == orgId &&
                        string.Equals(a.Ecosystem, ecosystem, StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();

        if (anchors.Count == 0)
        {
            return Task.FromResult<PgpPublicKeyRingBundle?>(null);
        }

        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var bundle = Dependably.Protocol.Provenance.PgpKeyRingBuilder.BuildFromAnchors(
            anchors, logger, ecosystem);
        return Task.FromResult(bundle);
    }

    public Task<IReadOnlyDictionary<string, byte[]>> GetNpmKeysAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = _anchors
            .Where(a => a.OrgId == orgId &&
                        string.Equals(a.Ecosystem, "npm", StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();

        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var map = Dependably.Protocol.Provenance.NpmSignatureKeyStore.BuildSpkiMap(anchors, logger);
        return Task.FromResult(map);
    }

    public Task<X509Certificate2Collection> GetNuGetAnchorsAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = _anchors
            .Where(a => a.OrgId == orgId &&
                        string.Equals(a.Ecosystem, "nuget", StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();

        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var certs = Dependably.Protocol.Provenance.NuGetSignatureTrustStore.ParseAnchors(anchors, logger);
        return Task.FromResult(certs);
    }

    public Task<Dependably.Protocol.Provenance.PyPiTrustMaterial> GetPyPiTrustAsync(
        string orgId, CancellationToken ct = default)
    {
        var anchors = _anchors
            .Where(a => a.OrgId == orgId &&
                        string.Equals(a.Ecosystem, "pypi", StringComparison.Ordinal))
            .Select(a => a.Material)
            .ToList();

        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        var material = anchors.Count == 0
            ? Dependably.Protocol.Provenance.PyPiTrustMaterial.Empty
            : Dependably.Protocol.Provenance.PyPiSigstoreTrustStore.BuildFromAnchors(anchors, logger);
        return Task.FromResult(material);
    }

    public void InvalidateTrustAnchorCache(string orgId)
    {
        // No-op for the stub — no caching in this test double.
    }
}
