using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>One advisory ready to link, with its stored row id when it is linked as already stored.</summary>
internal sealed record ResolvedAdvisory(OsvAdvisory Advisory, string? StoredVulnId);

/// <summary>
/// One purl's answer from a reached batch. <see cref="UnresolvedIds"/> names the advisories the
/// source matched to the purl but whose detail never arrived and that the instance does not hold
/// either; <see cref="Answered"/> is false when the source returned no list for the purl at all.
/// Either way the purl's answer is incomplete and it must not be recorded as screened.
/// </summary>
internal sealed record ResolvedPurlAdvisories(
    IReadOnlyList<ResolvedAdvisory> Advisories, IReadOnlyList<string> UnresolvedIds, bool Answered = true)
{
    public bool IsComplete => Answered && UnresolvedIds.Count == 0;
}

/// <summary>
/// Resolves the stripped (<see cref="OsvAdvisory.IsHydrated"/> false) records a reached batch query
/// can return. A stripped record carries no severity, score or affected data, so it is never
/// written; an id the instance already stores is linked from its stored row instead, and any other
/// stripped id leaves its purl unresolved. Dropping it and recording the purl as screened would
/// read the version as clean, and that stamp is what enables the malicious, KEV, EPSS and CVSS
/// block arms.
/// </summary>
internal static class BatchAdvisoryResolver
{
    public static async Task<List<ResolvedPurlAdvisories>> ResolveAsync(
        VulnerabilityRepository vulns, IReadOnlyList<List<OsvAdvisory>> results, CancellationToken ct)
    {
        var strippedIds = results
            .Where(list => list is not null)
            .SelectMany(list => list)
            .Where(a => !a.IsHydrated && !string.IsNullOrEmpty(a.Id))
            .Select(a => a.Id)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var stored = strippedIds.Count == 0
            ? new Dictionary<string, StoredAdvisory>(StringComparer.Ordinal)
            : await vulns.GetStoredAdvisoriesAsync(strippedIds, ct);

        return results.Select(list => Resolve(list, stored)).ToList();
    }

    private static ResolvedPurlAdvisories Resolve(
        List<OsvAdvisory>? advisories, IReadOnlyDictionary<string, StoredAdvisory> stored)
    {
        if (advisories is null)
        {
            return new ResolvedPurlAdvisories([], [], Answered: false);
        }

        var resolved = new List<ResolvedAdvisory>(advisories.Count);
        var unresolved = new List<string>();
        foreach (var advisory in advisories)
        {
            if (advisory.IsHydrated)
            {
                resolved.Add(new ResolvedAdvisory(advisory, null));
            }
            else if (!string.IsNullOrEmpty(advisory.Id) && stored.TryGetValue(advisory.Id, out var row))
            {
                resolved.Add(new ResolvedAdvisory(row.Advisory, row.VulnId));
            }
            else
            {
                unresolved.Add(advisory.Id);
            }
        }

        return new ResolvedPurlAdvisories(resolved, unresolved);
    }
}
