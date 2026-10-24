using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;

namespace Dependably.Api;

/// <summary>Evicts cached protocol metadata after a version delete, per ecosystem.</summary>
internal static class ProtocolMetadataEviction
{
    /// <summary>
    /// Invalidates any cached metadata for <paramref name="pkg"/> so a just-deleted version stops
    /// being served from cache. Shared by both <see cref="OrgController.DeleteVersion"/> branches (hosted and
    /// cache-plane) so eviction never drifts between the two delete paths, and routed through
    /// <see cref="MetadataInvalidationCoordinator"/> so it expands the identical variant matrix
    /// the protocol-plane publish paths use — and reaches peer replicas the same way.
    /// </summary>
    internal static void Evict(
        MetadataInvalidationCoordinator coordinator, string orgId, string ecosystem, Package pkg, string version)
    {
        var invalidation = ecosystem switch
        {
            "npm" => MetadataInvalidation.ForNpm(orgId, pkg.PurlName),
            "pypi" => MetadataInvalidation.ForPyPi(orgId, pkg.PurlName),
            "nuget" => MetadataInvalidation.ForNuGet(orgId, pkg.PurlName),
            // Maven package rows carry "groupId:artifactId" as their PURL name; a deleted
            // SNAPSHOT also changes the version-level build-list document.
            "maven" => MavenInvalidation(orgId, pkg.PurlName, version),
            "rpm" => MetadataInvalidation.ForRpm(orgId),
            _ => null,
        };

        if (invalidation is not null)
        {
            coordinator.Invalidate(invalidation);
        }
    }

    // Splits a Maven package row's "groupId:artifactId" PURL name back into its coordinates.
    // Returns null for a malformed name rather than inventing an empty groupId.
    private static MetadataInvalidation? MavenInvalidation(string orgId, string purlName, string version)
    {
        int separator = purlName.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == purlName.Length - 1)
        {
            return null;
        }

        bool isSnapshot = version.EndsWith("-SNAPSHOT", StringComparison.Ordinal);
        return MetadataInvalidation.ForMaven(
            orgId, purlName[..separator], purlName[(separator + 1)..], isSnapshot ? version : null);
    }
}
