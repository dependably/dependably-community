using System.Collections.Concurrent;
using Dependably.Protocol;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure.OciScan;

/// <summary>One advisory a scanner result names, and the package it was first matched on.</summary>
public sealed record OciScanAdvisoryRef(string Id, string Ecosystem, string PackageName);

/// <summary>
/// The outcome of resolving a result's advisory ids.
/// <list type="bullet">
///   <item><see cref="Resolved"/>: each id the instance can vouch for, mapped to its stored row.</item>
///   <item><see cref="Unknown"/>: ids the advisory source says it does not hold.</item>
///   <item><see cref="Unverified"/>: ids not confirmed either way this time: the source did not
///   answer for them, or they were past the per-result fetch cap or the fetch time budget.</item>
///   <item><see cref="SourceUnavailable"/>: the source answered none of the ids it was asked about,
///   which is an outage rather than a gap in what it holds.</item>
/// </list>
/// Unknown and unverified ids are never stored or linked; the caller records them as a coverage
/// gap, so an image whose advisories could not all be verified never reads clean.
/// </summary>
public sealed record OciScanAdvisoryResolution(
    IReadOnlyDictionary<string, StoredAdvisory> Resolved,
    IReadOnlySet<string> Unknown,
    IReadOnlySet<string> Unverified,
    bool SourceUnavailable);

/// <summary>
/// Turns the advisory ids a scanner result names into stored <c>vulnerabilities</c> rows without
/// ever storing the scanner's own copy of a record.
///
/// <para>That table is shared by every tenant: every org's gates, lookups and KEV/EPSS joins read
/// its score, severity and aliases. A scanner posts with one tenant's credential, so a record in
/// its body is that tenant's claim, not a fact. An id the instance already stores is linked as
/// stored. An id it does not is fetched by id from the registry's own advisory source
/// (<see cref="IOsvSource"/>: OSV.dev, or the sideloaded dumps under <c>OSV_MODE=local</c>) and
/// stored through the same upsert the registry's own scan uses. An id the source does not know, or
/// one it could not be asked about, is never stored or linked; a scanner's record is never the
/// fallback.</para>
///
/// <para>The source is the instance's shared OSV budget, so one result spends a bounded share of
/// it: ids are deduplicated, at most <see cref="OciScanOptions.AdvisoryFetchMax"/> unstored ids are
/// fetched, a few at a time, within <see cref="OciScanOptions.AdvisoryFetchBudget"/>; every record
/// fetched is stored as soon as the fetch phase ends, whatever happened to the others, so a retry
/// or the next match only asks for what is still missing; and an id the source reported unknown is
/// remembered for <see cref="UnknownTtl"/> (process-local, at most <see cref="UnknownCacheMax"/>
/// ids) and not asked about again meanwhile.</para>
/// </summary>
public sealed class OciScanAdvisoryResolver
{
    /// <summary>How long an id the source reported unknown is not asked about again.</summary>
    internal static readonly TimeSpan UnknownTtl = TimeSpan.FromHours(6);

    /// <summary>The most unknown ids remembered at once.</summary>
    internal const int UnknownCacheMax = 10_000;

    private const int MaxConcurrentFetches = 4;

    private readonly IOsvSource _osv;
    private readonly VulnerabilityRepository _vulns;
    private readonly OciScanOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger<OciScanAdvisoryResolver> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _unknownUntil = new(StringComparer.OrdinalIgnoreCase);

    public OciScanAdvisoryResolver(
        IOsvSource osv, VulnerabilityRepository vulns, OciScanOptions options, TimeProvider time,
        ILogger<OciScanAdvisoryResolver> logger)
    {
        _osv = osv;
        _vulns = vulns;
        _options = options;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Resolves <paramref name="refs"/>. When an id appears more than once, its first reference
    /// names the package a newly stored advisory is keyed to.
    /// </summary>
    public async Task<OciScanAdvisoryResolution> ResolveAsync(
        IEnumerable<OciScanAdvisoryRef> refs, CancellationToken ct = default)
    {
        var firstRefs = new Dictionary<string, OciScanAdvisoryRef>(StringComparer.Ordinal);
        foreach (var r in refs)
        {
            firstRefs.TryAdd(r.Id, r);
        }

        var stored = await _vulns.GetStoredAdvisoriesAsync(firstRefs.Keys, ct);
        var resolved = new Dictionary<string, StoredAdvisory>(stored, StringComparer.Ordinal);
        var unknown = new HashSet<string>(StringComparer.Ordinal);
        var unverified = new HashSet<string>(StringComparer.Ordinal);

        var now = _time.GetUtcNow();
        var toFetch = new List<string>();
        foreach (string id in firstRefs.Keys.Where(id => !stored.ContainsKey(id)))
        {
            if (_unknownUntil.TryGetValue(id, out var until) && until > now)
            {
                unknown.Add(id);
            }
            else if (toFetch.Count < _options.AdvisoryFetchMax)
            {
                toFetch.Add(id);
            }
            else
            {
                unverified.Add(id);
            }
        }

        if (toFetch.Count == 0)
        {
            return Finish(resolved, unknown, unverified, sourceUnavailable: false);
        }

        var fetched = await FetchAsync(toFetch, ct);
        int answered = 0;
        foreach (var (id, outcome) in fetched)
        {
            switch (outcome)
            {
                case FetchOutcome.Found found:
                    answered++;
                    var (ecosystem, packageName) = StoredPackage(found.Advisory, firstRefs[id]);
                    string vulnId = await _vulns.UpsertVulnerabilityAsync(found.Advisory, ecosystem, packageName, ct);
                    resolved[id] = new StoredAdvisory(vulnId, found.Advisory);
                    break;
                case FetchOutcome.NotHeld:
                    answered++;
                    unknown.Add(id);
                    RememberUnknown(id, now);
                    break;
                default:
                    unverified.Add(id);
                    break;
            }
        }

        // Every id the source was asked about went unanswered: an outage, not a gap in its data.
        // That includes a budget that ran out before the source answered anything, which under a
        // short lease can happen before the source's own client timeout would have reported it.
        bool sourceUnavailable = answered == 0
            && fetched.Any(f => f.Outcome is FetchOutcome.Unreached or FetchOutcome.OutOfBudget);
        return Finish(resolved, unknown, unverified, sourceUnavailable);
    }

    /// <summary>
    /// Whether a result for <paramref name="job"/> may still be refused for an advisory-source
    /// outage. A deferral costs no attempt, so it is bounded by time instead: within
    /// <see cref="OciScanOptions.RescanAge"/> of the job's first deferral, so time it spent queued
    /// before its first claim never shortens the window. Past that, the result is stored with its
    /// unverified advisories as a coverage gap (the image reads partial, never clean), so one
    /// advisory the source persistently cannot serve never holds an image back indefinitely; the
    /// sweep queues the image again a rescan age later, which asks the source again.
    /// </summary>
    public bool MayDefer(OciScanJob job) =>
        job.FirstDeferredAt is null
        || !DateTimeOffset.TryParse(
            job.FirstDeferredAt, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var firstDeferred)
        || _time.GetUtcNow() - firstDeferred < _options.RescanAge;

    /// <summary>
    /// The package a newly stored advisory row is keyed to, which the row keeps for good. The
    /// scanner's component is used only when the source's record names that same package
    /// (ecosystem and name); otherwise the record's own first affected package is, so a scanner
    /// cannot key a shared advisory to a package it does not describe. A record that names no
    /// package at all falls back to the component.
    /// </summary>
    internal static (string Ecosystem, string PackageName) StoredPackage(OsvAdvisory advisory, OciScanAdvisoryRef r)
    {
        var named = advisory.AffectedPackages.Where(p => !string.IsNullOrEmpty(p.Name)).ToList();
        if (named.Count == 0
            || named.Any(p => string.Equals(p.Name, r.PackageName, StringComparison.OrdinalIgnoreCase)
                && string.Equals(p.Ecosystem, r.Ecosystem, StringComparison.OrdinalIgnoreCase)))
        {
            return (r.Ecosystem, r.PackageName);
        }

        return (named[0].Ecosystem ?? r.Ecosystem, named[0].Name!);
    }

    private OciScanAdvisoryResolution Finish(
        Dictionary<string, StoredAdvisory> resolved, HashSet<string> unknown, HashSet<string> unverified,
        bool sourceUnavailable)
    {
        if (unknown.Count > 0 || unverified.Count > 0)
        {
            _logger.LogWarning(
                "OCI scan result: {Unknown} advisory id(s) unknown to the advisory source and {Unverified} not verified "
                + "(source unreachable, over the per-result fetch cap, or out of time); none were stored or linked.",
                unknown.Count, unverified.Count);
        }

        return new OciScanAdvisoryResolution(resolved, unknown, unverified, sourceUnavailable);
    }

    private void RememberUnknown(string id, DateTimeOffset now)
    {
        if (_unknownUntil.Count >= UnknownCacheMax)
        {
            foreach (var (key, until) in _unknownUntil)
            {
                if (until <= now)
                {
                    _unknownUntil.TryRemove(key, out _);
                }
            }

            if (_unknownUntil.Count >= UnknownCacheMax)
            {
                _unknownUntil.Clear();
            }
        }

        _unknownUntil[id] = now + UnknownTtl;
    }

    private abstract record FetchOutcome
    {
        public sealed record Found(OsvAdvisory Advisory) : FetchOutcome;

        public sealed record NotHeld : FetchOutcome;

        public sealed record Unreached : FetchOutcome;

        public sealed record OutOfBudget : FetchOutcome;
    }

    // Fetches each id a few at a time until the fetch budget runs out; an id not fetched by then
    // is out of budget. A record that is incomplete or answers for a different id is treated as
    // unreached: it cannot be stored, and the source may answer properly next time.
    private async Task<List<(string Id, FetchOutcome Outcome)>> FetchAsync(List<string> ids, CancellationToken ct)
    {
        using var budget = new CancellationTokenSource(_options.AdvisoryFetchBudget, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);
        using var gate = new SemaphoreSlim(MaxConcurrentFetches);
        var tasks = ids.Select(async id =>
        {
            try
            {
                await gate.WaitAsync(linked.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (id, (FetchOutcome)new FetchOutcome.OutOfBudget());
            }

            try
            {
                var lookup = await _osv.TryGetAdvisoryAsync(id, linked.Token);
                return (id, Classify(id, lookup));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // The resolver's budget firing is its own time running out; a cancellation
                // while the budget is still live is the source timing out, which is an outage.
                return (id, budget.IsCancellationRequested
                    ? new FetchOutcome.OutOfBudget()
                    : new FetchOutcome.Unreached());
            }
            finally
            {
                gate.Release();
            }
        });
        return (await Task.WhenAll(tasks)).ToList();
    }

    private static FetchOutcome Classify(string id, OsvIdLookupResult lookup) =>
        !lookup.Reached
            ? new FetchOutcome.Unreached()
            : lookup.Advisory is null
            ? new FetchOutcome.NotHeld()
            : lookup.Advisory.IsHydrated && string.Equals(lookup.Advisory.Id, id, StringComparison.OrdinalIgnoreCase)
            ? new FetchOutcome.Found(lookup.Advisory)
            : new FetchOutcome.Unreached();
}
