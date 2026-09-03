using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;

namespace Dependably.Protocol.Hex;

/// <summary>
/// Builds the registry resources this org serves from the three inputs the read plane has: the
/// releases this org holds on either plane, the upstream's own <c>Package</c> resource (already
/// signature- and origin-verified), and the block gate's verdicts. Pure: no I/O, so the merge
/// rules are testable on their own. The rules are the ones every other ecosystem's index applies —
/// a held release shadows the upstream's on a version collision, a version the download path
/// would refuse for a reason the index can know is not advertised, and the result is the org's
/// own repository, never a relabelled copy of the upstream's.
/// </summary>
public static class HexIndexBuilder
{
    /// <summary>
    /// The repository name embedded in every resource this registry signs. Fixed rather than
    /// per-org: tenancy is host-resolved, and a Hex client names the repository it registered,
    /// which the Setup snippet fixes to this value.
    /// </summary>
    public const string RepositoryName = "dependably";

    /// <summary>
    /// The releases advertised for one package, in the upstream's ascending order for upstream
    /// releases and publish order for held ones. <paramref name="held"/> shadows
    /// <paramref name="upstream"/> on a version collision; <paramref name="blockedHeld"/> names
    /// held versions the stored-state gate refuses; upstream-only releases are screened through
    /// <paramref name="policy"/> on the two facts the upstream index carries (publish time and
    /// retirement).
    /// </summary>
    public static HexPackage BuildPackage(
        string name,
        IReadOnlyList<HexIndexedRelease> held,
        HexPackage? upstream,
        IReadOnlySet<string> blockedHeld,
        IReadOnlyList<HexAdvisoryRow> advisories,
        BlockPolicy policy,
        DateTimeOffset now)
    {
        var releases = new List<HexRelease>();
        var ownerByVersion = new Dictionary<string, string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var r in held)
        {
            seen.Add(r.Version);
            if (blockedHeld.Contains(r.Version))
            {
                continue;
            }

            releases.Add(ToRelease(r));
            ownerByVersion[r.Version] = r.OwnerId;
        }

        if (upstream is not null)
        {
            foreach (var r in upstream.Releases)
            {
                if (!seen.Add(r.Version))
                {
                    continue;
                }

                // An upstream-only release carries exactly two decidable facts; the rest are
                // enforced at first fetch, which is what makes the download path the enforcement
                // point for every arm this index cannot see.
                var facts = VersionFacts.ForUpstreamOnly(
                    deprecated: r.Retired is { } retired ? RetirementAsDeprecation(retired) : null,
                    publishedAt: r.PublishedAt?.ToDateTimeOffset());
                if (!BlockGateService.Evaluate(facts, policy, now).Servable)
                {
                    continue;
                }

                releases.Add(r with { AdvisoryIndexes = null });
            }
        }

        releases.Sort((a, b) => EcosystemVersionOrdering.Compare("hex", a.Version, b.Version)
            ?? string.CompareOrdinal(a.Version, b.Version));

        var wire = AttachAdvisoryIndexes(releases, ownerByVersion, advisories);
        return new HexPackage(name, RepositoryName, releases, wire);
    }

    /// <summary>
    /// Indexes the advisories once on the package and rewrites each release that one touches to
    /// reference them by position, returning the package-level advisory list. Only releases with
    /// an owner id (held on either plane) can be touched, so an advisory naming no release in this
    /// index is left out of the list entirely rather than published with no referent.
    /// </summary>
    private static List<HexSecurityAdvisory> AttachAdvisoryIndexes(
        List<HexRelease> releases,
        Dictionary<string, string> ownerByVersion,
        IReadOnlyList<HexAdvisoryRow> advisories)
    {
        var wire = new List<HexSecurityAdvisory>();
        var indexesByOwner = new Dictionary<string, List<uint>>(StringComparer.Ordinal);
        foreach (var advisory in advisories)
        {
            if (advisory.OwnerIds.Count == 0)
            {
                continue;
            }

            uint index = (uint)wire.Count;
            foreach (string owner in advisory.OwnerIds)
            {
                if (!indexesByOwner.TryGetValue(owner, out var list))
                {
                    list = new List<uint>();
                    indexesByOwner[owner] = list;
                }

                list.Add(index);
            }

            wire.Add(HexAdvisoryRepository.ToWire(advisory));
        }

        for (int i = 0; i < releases.Count; i++)
        {
            if (ownerByVersion.TryGetValue(releases[i].Version, out string? owner)
                && indexesByOwner.TryGetValue(owner, out var indexes))
            {
                releases[i] = releases[i] with { AdvisoryIndexes = indexes };
            }
        }

        return wire;
    }

    /// <summary>The <c>/names</c> resource: every package this org holds on either plane.</summary>
    public static HexNames BuildNames(IReadOnlyList<(string Name, HexIndexedRelease Release)> held)
    {
        var names = held.Select(h => h.Name).Distinct(StringComparer.Ordinal).OrderBy(n => n, StringComparer.Ordinal);
        return new HexNames(RepositoryName, names.Select(n => new HexNameEntry(n)).ToList());
    }

    /// <summary>The <c>/versions</c> resource: every held package with its servable versions, retired and advisory index sets.</summary>
    public static HexVersions BuildVersions(
        IReadOnlyList<(string Name, HexIndexedRelease Release)> held,
        IReadOnlySet<(string Name, string Version)> blocked,
        IReadOnlySet<string> ownersWithAdvisories)
    {
        var entries = new List<HexVersionsEntry>();
        foreach (var group in held.GroupBy(h => h.Name, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var releases = group
                .Where(h => !blocked.Contains((h.Name, h.Release.Version)))
                .Select(h => h.Release)
                .OrderBy(r => r.Version, Comparer<string>.Create((a, b) =>
                    EcosystemVersionOrdering.Compare("hex", a, b) ?? string.CompareOrdinal(a, b)))
                .ToList();
            if (releases.Count == 0)
            {
                continue;
            }

            var retired = new List<int>();
            var withAdvisories = new List<int>();
            for (int i = 0; i < releases.Count; i++)
            {
                if (releases[i].Facts.RetiredReason is not null)
                {
                    retired.Add(i);
                }

                if (ownersWithAdvisories.Contains(releases[i].OwnerId))
                {
                    withAdvisories.Add(i);
                }
            }

            entries.Add(new HexVersionsEntry(group.Key, releases.Select(r => r.Version).ToList(), retired, withAdvisories));
        }

        return new HexVersions(RepositoryName, entries);
    }

    /// <summary>The block policy the org's settings describe, for the upstream-only screening above.</summary>
    public static BlockPolicy PolicyFrom(OrgSettings settings) =>
        new(MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            BlockRevokedMode: settings.BlockRevoked);

    /// <summary>A held release as the index advertises it.</summary>
    public static HexRelease ToRelease(HexIndexedRelease r) => new(
        r.Version,
        Convert.FromHexString(r.Facts.InnerChecksumHex),
        r.Facts.Requirements.Select(q => q.ToDependency()).ToList(),
        r.Facts.RetiredReason is { } reason ? new HexRetirementStatus(reason, r.Facts.RetiredMessage) : null,
        string.IsNullOrEmpty(r.OuterChecksumHex) ? null : Convert.FromHexString(r.OuterChecksumHex),
        null,
        r.PublishedAt is { } p ? HexTimestamp.FromDateTimeOffset(p) : null);

    /// <summary>
    /// The deprecation text the block gate's deprecated arm reads for a retired upstream release.
    /// Every retirement reason counts: Hex's protocol says a retired release "should only be
    /// resolved if it has already been locked", which is exactly what block_deprecated governs.
    /// </summary>
    public static string RetirementAsDeprecation(HexRetirementStatus retired) =>
        string.IsNullOrWhiteSpace(retired.Message)
            ? $"retired: {HexReleaseRepository.ReasonToWire(retired.Reason)}"
            : $"retired: {HexReleaseRepository.ReasonToWire(retired.Reason)} — {retired.Message}";
}
