using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Sbom;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for <see cref="SbomAuthorSigner"/>. <see cref="Unconfigured"/> builds a signer
/// with no <c>DEPENDABLY_MASTER_KEY</c> — <c>CanSign</c> is false and every export renders
/// unsigned, exactly as an install with no master key does — which is the shape almost every
/// <c>SbomExportService</c> test wants, since they assert on export content unrelated to
/// signing. <see cref="Configured"/> builds one that can actually sign, for tests of the
/// signature itself.
/// </summary>
public static class TestSbomAuthorSigner
{
    public static SbomAuthorSigner Unconfigured(IMetadataStore db, TimeProvider time) =>
        new(new SbomSigningKeyRepository(db, Protector(configured: false), time, TestEdgeMode.Disabled()));

    public static SbomAuthorSigner Configured(IMetadataStore db, TimeProvider time) =>
        new(new SbomSigningKeyRepository(db, Protector(configured: true), time, TestEdgeMode.Disabled()));

    /// <summary>
    /// Like <see cref="Configured"/>, but also hands back the backing
    /// <see cref="SbomSigningKeyRepository"/> — for a test that needs to force a key rotation
    /// (<see cref="SbomSigningKeyRepository.RotateAsync"/>) between two exports rather than only
    /// ever reading the org's first-minted key.
    /// </summary>
    public static (SbomAuthorSigner Signer, SbomSigningKeyRepository Keys) ConfiguredWithRepository(
        IMetadataStore db, TimeProvider time)
    {
        var keys = new SbomSigningKeyRepository(db, Protector(configured: true), time, TestEdgeMode.Disabled());
        return (new SbomAuthorSigner(keys), keys);
    }

    private static EnvelopeProtector Protector(bool configured)
    {
        var builder = new ConfigurationBuilder();
        if (configured)
        {
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
            });
        }

        return new EnvelopeProtector(new EnvFileMasterKeyProvider(builder.Build()));
    }
}
