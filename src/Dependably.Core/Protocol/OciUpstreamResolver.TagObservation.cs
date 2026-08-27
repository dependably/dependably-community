using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.Extensions.Options;

namespace Dependably.Protocol;

/// <summary>
/// The instance-wide, credential-scoped tag-observation cache and the revalidation/promotion
/// gate built on it. Concurrent callers sharing a credential identity collapse into one upstream
/// HEAD; a failure is never served from that cache, and a Found answer lives only as long as
/// ManifestTagTtl.
/// </summary>
public sealed partial class OciUpstreamResolver
{
    // ── Shared tag observation (instance-wide, credential-scoped) ─────────────

    // In-cache identity of one upstream tag observation. Fingerprint is what keeps the sharing
    // inside a single credential identity — see the _tagObservations field comment. It is spelled
    // without the Credential prefix so the component does not shadow the CredentialFingerprint
    // method below that produces its value.
    private readonly record struct OciTagObservationKey(
        string Host, string Repository, string Tag, string Fingerprint);

    private enum TagObservationKind { Found, NotFound, NoDigest }

    // One upstream answer to "what does this tag point at": the digest plus the HEAD header
    // metadata, stamped with when it was observed. Never carries manifest bytes — bodies are
    // always fetched per-org with that org's own credentials.
    private sealed record TagObservation(
        TagObservationKind Kind, string? Digest, string MediaType, long SizeBytes, DateTimeOffset ObservedAt);

    // Collapses the upstream credential material to an opaque identity. SHA-256 rather than the
    // raw values so secrets are not retained as dictionary keys; any difference in auth type,
    // username, password, or pinned token endpoint yields a different fingerprint and therefore
    // no sharing.
    private static string CredentialFingerprint(OciUpstreamRegistryOptions upstream)
    {
        string material = string.Join(
            '\n', (int)upstream.AuthType, upstream.Username, upstream.Password, upstream.TokenEndpoint);
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material)));
    }

    private bool IsObservationFresh(TagObservation obs) =>
        _time.GetUtcNow() - obs.ObservedAt < _options.Value.ManifestTagTtl;

    /// <summary>
    /// Answers "what digest does this tag point at upstream" through the shared observation
    /// cache: a fresh cached answer is reused without any network traffic; concurrent callers
    /// (across tenants sharing a credential identity) collapse into one upstream HEAD; and a
    /// miss issues the HEAD with the calling org's own credentials. Throws
    /// <see cref="OciUpstreamUnavailableException"/> (or a transport exception) when the
    /// upstream fails to answer.
    /// </summary>
    /// <summary>
    /// The answer to hand this caller from an already-completed cache entry, or null when the entry
    /// was a stale <c>Found</c> — the one completed state worth retrying, evicted here so the caller
    /// can loop into a fresh fetch.
    ///
    /// <para>NotFound/NoDigest is a definitive current answer for THIS caller, so it is returned,
    /// but evicted too so it is never served to a later caller from cache. Looping on it instead
    /// would refetch the same answer forever when the fetch completes synchronously (a stubbed or
    /// very fast upstream).</para>
    /// </summary>
    private TagObservation? TakeCompletedObservation(
        TagObservation done, KeyValuePair<OciTagObservationKey, Lazy<Task<TagObservation>>> pair)
    {
        if (done.Kind != TagObservationKind.Found)
        {
            _tagObservations.TryRemove(pair);
            return done;
        }

        if (IsObservationFresh(done))
        {
            return done;
        }

        _tagObservations.TryRemove(pair);
        return null;
    }

    /// <summary>
    /// Arranges for an in-flight or faulted entry to be evicted on completion unless it settles as
    /// a fresh <c>Found</c>, so a failure is never served from cache while a Found result stays
    /// until ManifestTagTtl old. TryRemove is pair-targeted and idempotent, so racing continuations
    /// cannot evict a newer generation. A faulted task still rethrows out of the caller's
    /// <c>WaitAsync</c> — it must propagate, never loop into a synchronous refetch storm.
    /// </summary>
    private void EvictWhenNotFound(
        Task<TagObservation> task, KeyValuePair<OciTagObservationKey, Lazy<Task<TagObservation>>> pair)
        => _ = task.ContinueWith(
            t =>
            {
                if (t.IsFaulted || t.IsCanceled || t.Result.Kind != TagObservationKind.Found)
                {
                    _tagObservations.TryRemove(pair);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

    private async Task<TagObservation> ObserveUpstreamTagAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string tag, CancellationToken ct)
    {
        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (_tagObservations.Count >= MaxTagObservations)
            {
                PruneTagObservations();
            }

            var lazy = _tagObservations.GetOrAdd(key, _ => new Lazy<Task<TagObservation>>(
                // CancellationToken.None inside the shared fetch: the answer is shared by every
                // caller with the same credential identity, so one caller's disconnect must not
                // fault the Lazy for the rest — same posture as the blob single-flight.
                () => FetchTagObservationAsync(orgId, upstream, repository, tag),
                LazyThreadSafetyMode.ExecutionAndPublication));
            var pair = new KeyValuePair<OciTagObservationKey, Lazy<Task<TagObservation>>>(key, lazy);
            var task = lazy.Value;

            if (task.IsCompletedSuccessfully)
            {
                if (TakeCompletedObservation(task.Result, pair) is { } settled)
                {
                    return settled;
                }

                // Stale Found: evicted above, so loop into a fresh fetch.
                continue;
            }

            EvictWhenNotFound(task, pair);

            // WaitAsync(ct) lets this caller abandon the wait without cancelling the shared HEAD.
            return await task.WaitAsync(ct);
        }
    }

    // Returns a still-fresh cached observation without ever touching the network, or null.
    // Used by the first-fetch path, where a direct GET-by-tag is otherwise the cheaper call.
    private TagObservation? TryGetFreshObservation(
        OciUpstreamRegistryOptions upstream, string repository, string tag)
    {
        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        return _tagObservations.TryGetValue(key, out var lazy)
            && lazy.IsValueCreated
            && lazy.Value.IsCompletedSuccessfully
            && lazy.Value.Result is { Kind: TagObservationKind.Found } done
            && IsObservationFresh(done)
            ? done
            : null;
    }

    // Records an observation derived from a digest-verified per-org GET-by-tag body, so
    // sequential callers (same credential identity) within the TTL reuse it without a HEAD.
    private void StoreTagObservation(
        OciUpstreamRegistryOptions upstream, string repository, string tag,
        string digest, string mediaType, long sizeBytes)
    {
        if (_tagObservations.Count >= MaxTagObservations)
        {
            PruneTagObservations();
        }

        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        var obs = new TagObservation(TagObservationKind.Found, digest, mediaType, sizeBytes, _time.GetUtcNow());
        _tagObservations[key] = new Lazy<Task<TagObservation>>(
            () => Task.FromResult(obs), LazyThreadSafetyMode.ExecutionAndPublication);
    }

    // Expiry-ordered pruning, mirroring OciUpstreamAuthService.PruneTokens: drop completed
    // stale/non-Found entries first, then evict oldest-observed completed entries while still
    // over the cap. In-flight entries are never pruned.
    private void PruneTagObservations()
    {
        foreach (var kv in _tagObservations)
        {
            if (kv.Value.IsValueCreated && kv.Value.Value.IsCompleted
                && (!kv.Value.Value.IsCompletedSuccessfully
                    || kv.Value.Value.Result.Kind != TagObservationKind.Found
                    || !IsObservationFresh(kv.Value.Value.Result)))
            {
                _tagObservations.TryRemove(kv);
            }
        }

        int overBy = _tagObservations.Count - MaxTagObservations + 1;
        if (overBy <= 0)
        {
            return;
        }

        foreach (var kv in _tagObservations
            .Where(e => e.Value.IsValueCreated && e.Value.Value.IsCompletedSuccessfully)
            .OrderBy(e => e.Value.Value.Result.ObservedAt)
            .Take(overBy))
        {
            _tagObservations.TryRemove(kv);
        }
    }

    // The shared HEAD that produces an observation. Issued with the creating org's credentials;
    // only callers whose upstream carries byte-identical credential material can ever share the
    // resulting entry (the fingerprint is part of the cache key).
    private async Task<TagObservation> FetchTagObservationAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string tag)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        var client = _http.CreateClient("OciUpstream");
        string logContext = $"OCI tag observation HEAD {repository}:{tag} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ManifestAcceptTypes, upstream, repository, "pull",
            logContext, CancellationToken.None);
        if (resp is null)
        {
            return new TagObservation(TagObservationKind.NotFound, null, "", 0, _time.GetUtcNow());
        }

        var meta = ExtractManifestMetadataFromHeadResponse(resp, repository, tag, upstream.Host);
        return meta is null
            ? new TagObservation(TagObservationKind.NoDigest, null, "", 0, _time.GetUtcNow())
            : new TagObservation(TagObservationKind.Found, meta.Digest, meta.MediaType, meta.SizeBytes, _time.GetUtcNow());
    }

    // ── Tag revalidation + promotion gate ─────────────────────────────────────

    // The org's oci_tags row for one tag, or all-null when the tag has never been recorded.
    private sealed record OciTagRow(
        string? Digest, string? LastRevalidated, string? PendingDigest, string? PendingFirstSeenAt);

    private async Task<OciTagRow> ReadTagRowAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var row = await conn.QuerySingleOrDefaultAsync<OciTagRow>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated, " +
            "pending_digest AS PendingDigest, pending_first_seen_at AS PendingFirstSeenAt " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });
        return row ?? new OciTagRow(null, null, null, null);
    }

    // A successful revalidation confirmed the accepted mapping: refresh the freshness stamp and
    // drop any pending observation (upstream no longer advertises it, so it must not stick).
    private async Task ConfirmTagUnchangedAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            "UPDATE oci_tags SET last_revalidated = @now, pending_digest = NULL, pending_first_seen_at = NULL " +
            "WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag, now = UtcTimestamp.Now(_time) });
    }

    // Records a newly observed digest as pending WITHOUT advancing the tag. pending_first_seen_at
    // resets only when the observed digest differs from the held pending one (upstream moved on
    // again — the stuck-pending case), so the promotion age keeps accruing across revalidations
    // that keep observing the same digest. refreshStamp marks the revalidation itself as
    // successful (the upstream answered; holding is a policy decision, not a failure) — the HEAD
    // path passes false when it wants the next GET-by-tag to revalidate and repoint promptly.
    private async Task HoldPendingDigestAsync(
        string orgId, string repository, string tag, string observedDigest, bool refreshStamp, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = UtcTimestamp.Now(_time);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            """
            UPDATE oci_tags SET
                pending_digest = @observed,
                pending_first_seen_at = CASE WHEN pending_digest = @observed THEN pending_first_seen_at ELSE @now END,
                last_revalidated = CASE WHEN @refresh = 1 THEN @now ELSE last_revalidated END
            WHERE org_id = @orgId AND repository = @repo AND tag = @tag
            """,
            new { orgId, repo = repository, tag, observed = observedDigest, now, refresh = refreshStamp ? 1 : 0 });
    }

    /// <summary>
    /// Whether a newly observed digest may be promoted onto the tag right now.
    ///
    /// <para>
    /// Age is measured from the FIRST LOCAL OBSERVATION of the digest
    /// (<c>oci_tags.pending_first_seen_at</c>) — deliberately NOT from the image config blob's
    /// <c>created</c> timestamp. That is a security requirement, not a convenience:
    /// <c>created</c> is publisher-controlled, so a malicious rebuild can backdate it and
    /// bypass the cooldown entirely, whereas the local observation clock is this instance's
    /// own and cannot be influenced by the publisher.
    /// </para>
    /// </summary>
    private bool IsPromotionAllowed(OciTagRow row, string observedDigest, int? minReleaseAgeHours)
    {
        if (minReleaseAgeHours is null or <= 0)
        {
            return true; // policy off — promote immediately, preserving pre-gate behaviour
        }

        return string.Equals(row.PendingDigest, observedDigest, StringComparison.OrdinalIgnoreCase)
            && row.PendingFirstSeenAt is not null
            && DateTimeOffset.TryParse(
                row.PendingFirstSeenAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var firstSeen)
            && _time.GetUtcNow() - firstSeen >= TimeSpan.FromHours(minReleaseAgeHours.Value);
    }

    private async Task<int?> GetMinReleaseAgeHoursAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int?>(
            "SELECT min_release_age_hours FROM org_settings WHERE org_id = @orgId",
            new { orgId });
    }

    // Serves the digest the tag currently (still) resolves to: from the local cache when
    // present, otherwise re-fetched by digest from upstream with this org's own credentials —
    // a by-digest fetch is content-addressed and never touches the tag row, so an evicted
    // accepted manifest does not make a promotion-held or unchanged tag unavailable.
    private async Task<OciManifestResult?> ServeAcceptedDigestAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string digest, CancellationToken ct)
        => await TryGetCachedManifestByDigestAsync(orgId, digest, ct)
            ?? await FetchAndCacheManifestAsync(upstream, orgId, repository, digest, ct);

    /// <summary>
    /// Revalidates (or first-fetches) a tag reference against upstream, applying the promotion
    /// gate. The three policies stay orthogonal here: the TTL decided that this method runs at
    /// all (the caller found the entry stale); <c>min_release_age_hours</c> decides only whether
    /// a newly observed digest may be PROMOTED (a too-young digest keeps the previously
    /// accepted one serving — never an unavailable tag); and the stale grace lives in the
    /// controller, on the failure path of the upstream calls made here.
    /// </summary>
    private async Task<OciManifestResult?> RevalidateOrFetchTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag, CancellationToken ct)
    {
        var row = await ReadTagRowAsync(orgId, repository, tag, ct);
        if (row.Digest is null)
        {
            // First local sighting of the tag: there is no accepted digest the promotion gate
            // could hold the tag AT, and min_release_age gates promotion, never availability —
            // so the first resolution always lands. A fresh shared observation (another
            // caller's recent answer under the same credential identity) skips the upstream
            // ask entirely; otherwise a direct GET-by-tag is the cheaper single round-trip.
            var cachedObs = TryGetFreshObservation(upstream, repository, tag);
            if (cachedObs?.Digest is { } observedDigest)
            {
                var promoted = await PromoteTagAsync(upstream, orgId, repository, tag, observedDigest, ct);
                if (promoted is not null)
                {
                    return promoted;
                }
            }

            return await FetchAndCacheManifestAsync(upstream, orgId, repository, tag, ct);
        }

        int? minAgeHours = await GetMinReleaseAgeHoursAsync(orgId, ct);
        var obs = await ObserveUpstreamTagAsync(orgId, upstream, repository, tag, ct);
        return obs.Kind switch
        {
            // A definitive upstream "this tag does not exist" is a genuine miss — the one case
            // that correctly becomes MANIFEST_UNKNOWN. Upstream errors never reach here; they
            // throw out of ObserveUpstreamTagAsync into the controller's stale-if-error handling.
            TagObservationKind.NotFound => null,
            // Registry answered HEAD without a usable digest: revalidate the legacy way with a
            // full GET by tag, gating the repoint on the digest computed from the verified body.
            TagObservationKind.NoDigest => await RevalidateWithBodyAsync(
                upstream, orgId, repository, tag, row, minAgeHours, ct),
            _ => await ApplyRevalidationAsync(
                upstream, orgId, repository, tag, row, minAgeHours, obs.Digest!, ct),
        };
    }

    // Applies one successful upstream observation to the org's tag row: confirm, promote, or
    // hold-pending — and serve whichever digest the tag resolves to after that decision.
#pragma warning disable S107 // Revalidation threads the routing context (upstream/org/repo/tag) plus the decision inputs (row, policy, observation)
    private async Task<OciManifestResult?> ApplyRevalidationAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        OciTagRow row, int? minAgeHours, string observedDigest, CancellationToken ct)
#pragma warning restore S107
    {
        if (string.Equals(observedDigest, row.Digest, StringComparison.OrdinalIgnoreCase))
        {
            await ConfirmTagUnchangedAsync(orgId, repository, tag, ct);
            return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
        }

        if (IsPromotionAllowed(row, observedDigest, minAgeHours))
        {
            var promoted = await PromoteTagAsync(upstream, orgId, repository, tag, observedDigest, ct);
            if (promoted is not null)
            {
                return promoted;
            }

            // The observed digest vanished between the HEAD and the by-digest fetch (an
            // upstream mid-repoint). The accepted mapping is still the best true answer.
            return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
        }

        // Too young to promote: record (or keep aging) the observation and keep serving the
        // previously accepted digest. The revalidation itself succeeded, so the stamp refreshes —
        // the next upstream ask comes after another TTL, by which time the pending digest has
        // aged that much further.
        await HoldPendingDigestAsync(orgId, repository, tag, observedDigest, refreshStamp: true, ct);
        return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
    }

    // Legacy-shaped revalidation for registries whose HEAD carries no Docker-Content-Digest:
    // one GET by tag, promotion gated on the digest computed from the verified body.
    private async Task<OciManifestResult?> RevalidateWithBodyAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        OciTagRow row, int? minAgeHours, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        var m = await TryFetchManifestAsync(orgId, upstream, repository, tag, url, ct);
        if (m is null)
        {
            return null;
        }

        StoreTagObservation(upstream, repository, tag, m.Digest, m.MediaType, m.Bytes.Length);

        if (string.Equals(m.Digest, row.Digest, StringComparison.OrdinalIgnoreCase)
            || IsPromotionAllowed(row, m.Digest, minAgeHours))
        {
            // Unchanged (repoint is a no-op that refreshes the stamp) or promotable: the full
            // cache-and-repoint path, which writes the body before the tag as always.
            return await CacheAndReturnManifestAsync(upstream, orgId, repository, tag, m, ct);
        }

        await HoldPendingDigestAsync(orgId, repository, tag, m.Digest, refreshStamp: true, ct);
        return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
    }

    /// <summary>
    /// Promotes a tag to a newly observed digest: fetches the manifest body BY DIGEST with this
    /// org's own credentials (digest-verified by <see cref="TryFetchManifestAsync"/>), caches
    /// it, and only then repoints the tag — the write ordering that guarantees a tag never
    /// points at a digest whose manifest body is absent. Returns null when the digest is no
    /// longer fetchable upstream (nothing is written in that case).
    /// </summary>
    private async Task<OciManifestResult?> PromoteTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        string digest, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{digest}";
        var m = await TryFetchManifestAsync(orgId, upstream, repository, digest, url, ct);
        if (m is null)
        {
            return null;
        }

        var result = await CacheAndReturnManifestAsync(upstream, orgId, repository, digest, m, ct);
        await RepointTagAsync(upstream, orgId, repository, tag, m, ct);
        return result;
    }
}
