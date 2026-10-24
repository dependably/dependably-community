using Dapper;
using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// One-shot background rescan of npm tarballs stored before the ingest paths refused a tarball with
/// several top-level manifests. Ingest is the only place a tarball is checked on its way in; the
/// blob store is trusted afterwards and nothing is re-read per download. Artefacts already stored
/// get this pass instead: every npm <c>cache_artifact</c> row and every uploaded npm version is read
/// once, and one whose manifest is ambiguous or unscannable is flagged with facts the existing gates
/// already read. <c>has_install_script</c> is set with <see cref="AmbiguousKind"/> or
/// <see cref="UnscannableKind"/>, and the licence rows recorded from the first manifest are deleted
/// (a proxy row's <c>license_checked_at</c> is also cleared so the licence backfill re-reads it and
/// finds nothing), so the licence gate sees an unknown licence. The flag drives the install-script
/// gate whenever the tenant has it enabled.
/// <para>
/// A tick reads at most <see cref="MaxBlobsPerTick"/> blobs, and <c>NpmManifestRescanService</c> ticks every few
/// minutes until the marker is written. Each plane's keyset cursor is persisted
/// in <c>instance_settings</c>, so a large registry finishes over several ticks and a restart resumes
/// where the last tick stopped. A row whose blob cannot be read is retried on later ticks, and flagged
/// as unscannable after <see cref="MaxAttempts"/> failed attempts. Attempts are counted only while the
/// plane's own store is answering: the cache and registry tiers can be backed by different services,
/// so a batch with no successful read from that plane and many failures (or none read from it yet this
/// tick) is a storage outage, and the tick stops without counting anything and without moving the
/// cursor. Retries are gated the same way, per plane, by a canary read of a few other rows. A marker, written only once
/// both planes are done with no retryable failure outstanding, stops the pass repeating.
/// </para>
/// </summary>
public sealed class NpmManifestRescan(
    IMetadataStore db, TieredBlobStorage blobs, TimeProvider time, ILogger<NpmManifestRescan> logger)
{
    /// <summary>The background job name <c>DISABLE_BACKGROUND_JOBS</c> and <see cref="IAirGapMode"/> use for this pass.</summary>
    public const string JobName = "npm-manifest-rescan";

    /// <summary>Marker in <c>instance_settings</c> recording that the rescan has completed.</summary>
    internal const string MarkerKey = "npm_ambiguous_manifest_rescan_v1";

    internal const string CursorKeyPrefix = "npm_ambiguous_manifest_rescan_v1_cursor:";
    internal const string FailKeyPrefix = "npm_ambiguous_manifest_rescan_v1_fail:";
    private const string CursorEnd = "\u0001end";

    /// <summary>Install-script kind recorded for a tarball with several top-level manifests.</summary>
    public const string AmbiguousKind = "npm:ambiguous-manifest";

    /// <summary>Install-script kind recorded for a tarball that could not be scanned to the end.</summary>
    public const string UnscannableKind = "npm:unscannable-manifest";

    internal const int StartRows = 100;
    internal const int MinRows = 10;
    internal const int MaxRows = 500;

    /// <summary>
    /// Upper bound on blobs read in one tick. Caps blob reads and scanning so a first pass over a
    /// large registry spreads across several ticks instead of monopolising the backfill job.
    /// </summary>
    internal const int MaxBlobsPerTick = 2_000;

    /// <summary>Failed reads of one row before the rescan stops retrying it.</summary>
    internal const int MaxAttempts = 3;

    /// <summary>
    /// Failures in a batch with no successful read at which the blob store is judged unavailable. A
    /// batch with no success and fewer failures than this is also an outage while the tick has not yet
    /// read anything successfully.
    /// </summary>
    internal const int StoreOutageThreshold = 5;

    private sealed record Row(string Id, string BlobKey);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3604:Member initializer values should not be redundant",
        Justification = "The members are initialized from primary-constructor parameters; the rule misreads that as a "
                        + "redundant initializer.")]
    private sealed class PassState(int allowance)
    {
        public int Allowance = allowance;
        public int Scanned;
        public int Flagged;
        public int Missing;
        public int Failed;
        public HashSet<string> FailedThisTick { get; } = [];
        public HashSet<string> GivenUp { get; } = [];
        public Dictionary<string, int> SuccessesByPlane { get; } = [];
        public bool Outage;
    }

    // Reads of one scan page or one retry set. Failures are held back until the batch is judged, so a
    // storage outage is told apart from a handful of unreadable blobs before any attempt is counted.
    private sealed class Batch
    {
        public int Successes;
        public List<(string FailKey, int Attempts, string RowId, Exception Error)> Failures { get; } = [];
    }

    private sealed record Plane(
        string Name,
        Func<string, int, CancellationToken, Task<Row[]>> ReadPage,
        Func<string, CancellationToken, Task<Row?>> Lookup,
        Func<string, List<string>, WriteLockBudget, CancellationToken, Task> Flag,
        IBlobStore Store);

    /// <summary>
    /// Runs one tick of the rescan unless the marker is present. Returns the number of rows flagged
    /// this tick, or -1 when the marker was already present.
    /// </summary>
    // xtenant: cache_artifact and instance_settings are global tables (no org_id).
    public async Task<int> RunOnceAsync(int? batchRows = null, int? maxBlobs = null, CancellationToken ct = default)
    {
        if (await ReadSettingAsync(MarkerKey, ct) is not null)
        {
            return -1;
        }

        var budget = batchRows is int n ? new WriteLockBudget(n, n, n) : new WriteLockBudget(StartRows, MinRows, MaxRows);
        var state = new PassState(maxBlobs ?? MaxBlobsPerTick);
        var planes = new[] { CachePlane(), VersionPlane() };

        foreach (var plane in planes)
        {
            await ScanPlaneAsync(plane, budget, state, ct);
            if (state.Outage)
            {
                return state.Flagged;
            }
        }

        bool planesDone = true;
        foreach (var plane in planes)
        {
            planesDone &= await ReadSettingAsync(CursorKeyPrefix + plane.Name, ct) == CursorEnd;
        }

        int outstanding = -1;
        if (planesDone)
        {
            await RetryFailuresAsync(planes, budget, state, ct);
            if (state.Outage)
            {
                return state.Flagged;
            }

            outstanding = await CountOutstandingAsync(ct);
        }

        logger.LogInformation(
            "npm manifest rescan tick scanned {Scanned} tarball(s), flagged {Flagged}, skipped {Missing} missing blob(s), {Failed} unreadable; complete={Complete}.",
            state.Scanned, state.Flagged, state.Missing, state.Failed, planesDone && outstanding == 0);
        if (planesDone && outstanding == 0)
        {
            await WriteSettingAsync(MarkerKey, "1", ct);
            foreach (var (key, _) in await ListFailuresAsync(ct))
            {
                await DeleteSettingAsync(key, ct);
            }
        }

        return state.Flagged;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "An IN list built by DapperInClause.Expand: only generated @name placeholders are spliced, every "
                        + "value is bound; the rest is constant SQL text.")]
    private Plane CachePlane() => new(
        "cache",
        async (after, rows, ct) =>
        {
            await using var conn = await db.OpenAsync(ct);
            // xtenant: cache_artifact is a global table (no org_id).
            return (await conn.QueryAsync<Row>(new CommandDefinition(
                """
                SELECT id AS Id, blob_key AS BlobKey FROM cache_artifact
                WHERE ecosystem = 'npm' AND id > @after
                ORDER BY id
                LIMIT @rows
                """,
                new { after, rows }, cancellationToken: ct))).ToArray();
        },
        async (id, ct) =>
        {
            await using var conn = await db.OpenAsync(ct);
            // xtenant: cache_artifact is a global table (no org_id).
            return await conn.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
                "SELECT id AS Id, blob_key AS BlobKey FROM cache_artifact WHERE ecosystem = 'npm' AND id = @id",
                new { id }, cancellationToken: ct));
        },
        async (kind, ids, budget, ct) =>
        {
            var (clause, parameters) = DapperInClause.Expand("o", ids);
            parameters.Add("kind", kind);
            await using var conn = await db.OpenAsync(ct);
            // rawsql: clause is a parameterized IN (@o0, …) list built in C# by DapperInClause.
            // xtenant: UPDATE keyed by cache_artifact PK (global); no org_id needed.
            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE cache_artifact SET has_install_script = 1, install_script_kind = @kind, license_checked_at = NULL WHERE id IN " + clause,
                parameters, commandTimeout: 600, cancellationToken: ct));
            // rawsql: clause is a parameterized IN (@o0, …) list built in C# by DapperInClause.
            // xtenant: licence rows of a proxy cache_artifact are keyed by cache_artifact_id, a global id.
            await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM package_version_licenses WHERE owner_kind = 'cache_artifact' AND source = 'upstream' AND cache_artifact_id IN " + clause,
                parameters, commandTimeout: 600, cancellationToken: ct));
        },
        blobs.Cache);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "An IN list built by DapperInClause.Expand: only generated @name placeholders are spliced, every "
                        + "value is bound; the rest is constant SQL text.")]
    private Plane VersionPlane() => new(
        "versions",
        async (after, rows, ct) =>
        {
            // xtenant: the rescan covers uploaded versions of every tenant; pages are keyed by version id.
            await using var conn = await db.OpenCrossTenantAsync("npm manifest rescan of uploaded versions", ct);
            // xtenant: cross-tenant sweep by version id; the connection is the cross-tenant one.
            return (await conn.QueryAsync<Row>(new CommandDefinition(
                // plane-ok: uploaded-plane scan; the proxy plane is scanned by the cache_artifact plane of this class.
                """
                SELECT pv.id AS Id, pv.blob_key AS BlobKey
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.ecosystem = 'npm' AND pv.id > @after
                ORDER BY pv.id
                LIMIT @rows
                """,
                new { after, rows }, cancellationToken: ct))).ToArray();
        },
        async (id, ct) =>
        {
            // xtenant: retry of a single uploaded version by primary key.
            await using var conn = await db.OpenCrossTenantAsync("npm manifest rescan retry of an uploaded version", ct);
            // xtenant: cross-tenant lookup by version id; the connection is the cross-tenant one.
            return await conn.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
                // plane-ok: uploaded-plane lookup; the proxy plane is the cache_artifact plane of this class.
                """
                SELECT pv.id AS Id, pv.blob_key AS BlobKey
                FROM package_versions pv
                JOIN packages p ON p.id = pv.package_id
                WHERE p.ecosystem = 'npm' AND pv.id = @id
                """,
                new { id }, cancellationToken: ct));
        },
        async (kind, ids, budget, ct) =>
        {
            var (clause, parameters) = DapperInClause.Expand("o", ids);
            parameters.Add("kind", kind);
            // xtenant: flag write for versions of every tenant, keyed by version primary key.
            await using var conn = await db.OpenCrossTenantAsync("npm manifest rescan flags uploaded versions", ct);
            // rawsql: clause is a parameterized IN (@o0, …) list built in C# by DapperInClause.
            // xtenant: UPDATE keyed by package_versions PK on the cross-tenant connection.
            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE package_versions SET has_install_script = 1, install_script_kind = @kind WHERE id IN " + clause,
                parameters, commandTimeout: 600, cancellationToken: ct));
            // rawsql: clause is a parameterized IN (@o0, …) list built in C# by DapperInClause.
            // xtenant: licence rows keyed by package_version_id on the cross-tenant connection.
            // Both sources an npm version's tarball can write are deleted: 'upstream' (publish) and
            // 'uploaded' (import). Any other source is not read from the tarball and survives.
            await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM package_version_licenses WHERE owner_kind = 'package_version' AND source IN ('upstream', 'uploaded') AND package_version_id IN " + clause,
                parameters, commandTimeout: 600, cancellationToken: ct));
        },
        blobs.Registry);

    private async Task ScanPlaneAsync(Plane plane, WriteLockBudget budget, PassState state, CancellationToken ct)
    {
        string cursorKey = CursorKeyPrefix + plane.Name;
        string after = await ReadSettingAsync(cursorKey, ct) ?? "";
        if (after == CursorEnd)
        {
            return;
        }

        var pause = TimeSpan.Zero;
        while (state.Allowance > 0)
        {
            ct.ThrowIfCancellationRequested();
            var page = await plane.ReadPage(after, Math.Min(budget.Rows, state.Allowance), ct);
            if (page.Length == 0)
            {
                await WriteSettingAsync(cursorKey, CursorEnd, ct);
                return;
            }

            state.Allowance -= page.Length;
            var flagged = new Dictionary<string, List<string>>();
            var batch = new Batch();
            foreach (var row in page)
            {
                ct.ThrowIfCancellationRequested();
                await ClassifyAsync(plane, row, state, batch, flagged, attemptsSoFar: 0, ct);
            }

            if (await CommitBatchAsync(plane, batch, flagged, state, judgeOutage: true, ct))
            {
                return;
            }

            pause = await FlagAsync(plane, flagged, budget, pause, ct);
            after = page[^1].Id;
            await WriteSettingAsync(cursorKey, after, ct);
        }
    }

    private async Task<TimeSpan> FlagAsync(
        Plane plane, Dictionary<string, List<string>> flagged, WriteLockBudget budget, TimeSpan pause, CancellationToken ct)
    {
        if (flagged.Count == 0)
        {
            return pause;
        }

        if (pause > TimeSpan.Zero)
        {
            await Task.Delay(pause, time, ct);
        }

        long start = time.GetTimestamp();
        foreach (var (kind, ids) in flagged)
        {
            await plane.Flag(kind, ids, budget, ct);
        }

        var held = time.GetElapsedTime(start);
        budget.Record(held);
        return held;
    }

    // Reads and classifies one row. A missing blob is logged and skipped; a failed read is held in the
    // batch, and CommitBatchAsync records an attempt against the row so a later tick retries it, up to
    // MaxAttempts.
    private async Task ClassifyAsync(
        Plane plane, Row row, PassState state, Batch batch, Dictionary<string, List<string>> flagged, int attemptsSoFar, CancellationToken ct)
    {
        string failKey = FailKeyPrefix + plane.Name + ":" + row.Id;
        try
        {
            // blobkey-ok: blob_key read from the row; bytes live in the tier it was written to.
            await using var stream = await plane.Store.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
            if (stream is null)
            {
                batch.Successes++;
                state.Missing++;
                logger.LogWarning("npm manifest rescan skipped {Plane} {Id}: blob is missing.", plane.Name, row.Id);
                await DeleteSettingAsync(failKey, ct);
                return;
            }

            var outcome = NpmTarballManifestScanner.ScanClassified(stream, leaveOpen: true).Outcome;
            if (outcome == NpmManifestScanOutcome.ReadFailed)
            {
                throw new IOException("The npm tarball could not be read to completion.");
            }

            batch.Successes++;
            state.Scanned++;
            await DeleteSettingAsync(failKey, ct);
            if (!NpmTarballManifestScanner.IsRefusable(outcome))
            {
                return;
            }

            string kind = outcome == NpmManifestScanOutcome.Ambiguous ? AmbiguousKind : UnscannableKind;
            AddFlag(flagged, kind, row.Id);
            state.Flagged++;
            logger.LogWarning("npm manifest rescan flagged {Plane} {Id} as {Kind}.", plane.Name, row.Id, kind);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            batch.Failures.Add((failKey, attemptsSoFar + 1, row.Id, ex));
        }
    }

    // Judges a finished batch. A batch with no successful read and either many failures or no earlier
    // success in the tick is a storage outage: its failures are dropped uncounted and the tick stops,
    // because a blob the store cannot return cannot be served either. Otherwise the failures are
    // committed, and a row that has failed MaxAttempts times is flagged like an unscannable archive.
    // Returns true when the tick must stop.
    private async Task<bool> CommitBatchAsync(
        Plane plane, Batch batch, Dictionary<string, List<string>> flagged, PassState state, bool judgeOutage, CancellationToken ct)
    {
        if (judgeOutage && batch.Failures.Count > 0 && batch.Successes == 0
            && (batch.Failures.Count >= StoreOutageThreshold || state.SuccessesByPlane.GetValueOrDefault(plane.Name) == 0))
        {
            state.Outage = true;
            logger.LogWarning(
                "blob store unavailable; npm manifest rescan stopped for this tick without counting attempts. Plane={Plane} Failures={Failures}",
                plane.Name, batch.Failures.Count);
            return true;
        }

        state.SuccessesByPlane[plane.Name] = state.SuccessesByPlane.GetValueOrDefault(plane.Name) + batch.Successes;
        foreach (var (failKey, attempts, rowId, error) in batch.Failures)
        {
            state.Failed++;
            state.FailedThisTick.Add(failKey);
            logger.LogWarning(error, "npm manifest rescan could not read {Plane} {Id} (attempt {Attempt} of {MaxAttempts}): {ExceptionType}",
                plane.Name, rowId, attempts, MaxAttempts, error.GetType().Name);
            if (attempts < MaxAttempts)
            {
                await WriteSettingAsync(failKey, attempts.ToString(System.Globalization.CultureInfo.InvariantCulture), ct);
                continue;
            }

            // A row that stays unreadable while the store answers for other blobs cannot be shown
            // clean, so it is flagged like an unscannable archive rather than dropped. Its retry key is
            // cleared once the flag is written, so a failed flag write leaves the row retryable.
            logger.LogWarning(
                "npm manifest rescan gives up on {Plane} {Id} after {MaxAttempts} unreadable attempts and flags it as {Kind}.",
                plane.Name, rowId, MaxAttempts, UnscannableKind);
            AddFlag(flagged, UnscannableKind, rowId);
            state.Flagged++;
            state.GivenUp.Add(failKey);
        }

        return false;
    }

    private static void AddFlag(Dictionary<string, List<string>> flagged, string kind, string id)
    {
        if (!flagged.TryGetValue(kind, out var ids))
        {
            flagged[kind] = ids = [];
        }

        ids.Add(id);
    }

    // Retries rows whose blob could not be read on an earlier tick, once per tick, after both planes
    // have been swept. A row deleted since is dropped from the retry set.
    private async Task RetryFailuresAsync(Plane[] planes, WriteLockBudget budget, PassState state, CancellationToken ct)
    {
        foreach (var plane in planes)
        {
            string prefix = FailKeyPrefix + plane.Name + ":";
            var pending = (await ListFailuresAsync(ct))
                .Where(f => f.Key.StartsWith(prefix, StringComparison.Ordinal) && f.Attempts < MaxAttempts)
                .ToList();
            if (pending.Count > 0 && !await StoreAnswersAsync(plane, ct))
            {
                state.Outage = true;
                logger.LogWarning(
                    "blob store unavailable; npm manifest rescan stopped retrying this plane for this tick without counting attempts. Plane={Plane} Failures={Failures}",
                    plane.Name, pending.Count);
                continue;
            }

            var flagged = new Dictionary<string, List<string>>();
            var batch = new Batch();
            foreach (var (key, attempts) in await ListFailuresAsync(ct))
            {
                if (!key.StartsWith(prefix, StringComparison.Ordinal) || attempts >= MaxAttempts || state.Allowance <= 0 || state.FailedThisTick.Contains(key))
                {
                    continue;
                }

                state.Allowance--;
                var row = await plane.Lookup(key[prefix.Length..], ct);
                if (row is null)
                {
                    await DeleteSettingAsync(key, ct);
                    continue;
                }

                await ClassifyAsync(plane, row, state, batch, flagged, attempts, ct);
            }

            await CommitBatchAsync(plane, batch, flagged, state, judgeOutage: false, ct);
            await FlagAsync(plane, flagged, budget, TimeSpan.Zero, ct);
            foreach (string key in state.GivenUp.Where(k => k.StartsWith(FailKeyPrefix + plane.Name + ":", StringComparison.Ordinal)).ToList())
            {
                await DeleteSettingAsync(key, ct);
                state.GivenUp.Remove(key);
            }
        }
    }

    // Canary for the retry phase, whose batches are too small to judge on their own: a plane's store
    // is answering when a read of any of the first few rows of that plane returns, even with
    // "missing". Each plane is probed through its own store, because the cache and registry tiers can
    // be backed by different services and one answering says nothing about the other.
    private async Task<bool> StoreAnswersAsync(Plane plane, CancellationToken ct)
    {
        bool probed = false;
        foreach (var row in await plane.ReadPage("", StoreOutageThreshold, ct))
        {
            probed = true;
            try
            {
                // blobkey-ok: blob_key read from the row; bytes live in the tier it was written to.
                await using var stream = await plane.Store.GetAsync(BlobKeys.StoreKey(row.BlobKey), ct);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogDebug(ex, "npm manifest rescan canary read failed for {Plane} {Id}.", plane.Name, row.Id);
            }
        }

        return !probed;
    }

    /// <summary>True once the completion marker is written, so no further tick has work to do.</summary>
    public async Task<bool> IsCompleteAsync(CancellationToken ct = default) =>
        await ReadSettingAsync(MarkerKey, ct) is not null;

    private async Task<int> CountOutstandingAsync(CancellationToken ct) =>
        (await ListFailuresAsync(ct)).Count(f => f.Attempts < MaxAttempts);

    private async Task<List<(string Key, int Attempts)>> ListFailuresAsync(CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Key, string Value)>(new CommandDefinition(
            "SELECT key AS Key, value AS Value FROM instance_settings WHERE substr(key, 1, @len) = @prefix",
            new { len = FailKeyPrefix.Length, prefix = FailKeyPrefix }, cancellationToken: ct));
        return rows
            .Where(r => r.Key.StartsWith(FailKeyPrefix, StringComparison.Ordinal))
            .Select(r => (r.Key, int.TryParse(r.Value, out int a) ? a : MaxAttempts))
            .ToList();
    }

    private async Task<string?> ReadSettingAsync(string key, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<string>(new CommandDefinition(
            "SELECT value FROM instance_settings WHERE key = @key", new { key }, cancellationToken: ct));
    }

    private async Task WriteSettingAsync(string key, string value, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO instance_settings (key, value) VALUES (@key, @value)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value
            """,
            new { key, value }, cancellationToken: ct));
    }

    private async Task DeleteSettingAsync(string key, CancellationToken ct)
    {
        await using var conn = await db.OpenAsync(ct);
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM instance_settings WHERE key = @key", new { key }, cancellationToken: ct));
    }
}
