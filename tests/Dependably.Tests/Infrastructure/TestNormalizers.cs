using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for a <see cref="LicenseNormalizer"/> over a metadata store. The normalizer
/// reads the seeded <c>spdx_license</c> reference table once and caches its maps, so tests can
/// share one instance per store.
/// </summary>
public static class TestNormalizers
{
    public static LicenseNormalizer License(IMetadataStore db)
        => new(db, NullLogger<LicenseNormalizer>.Instance);
}
