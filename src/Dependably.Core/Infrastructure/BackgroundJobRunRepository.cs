using System.Diagnostics.CodeAnalysis;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Inputs to <see cref="BackgroundJobRunRepository.RecordAsync"/>. Bundled into a record so the
/// caller surface stays under the cognitive-load parameter limit.
/// </summary>
public sealed record BackgroundJobRunRecord(
    string Id,
    string JobName,
    string Operation,
    string RunId,
    DateTimeOffset StartedAt,
    DateTimeOffset FinishedAt,
    long DurationMs,
    string Outcome,
    string? ErrorMessage);

/// <summary>
/// Filter, sort, and pagination inputs for <see cref="BackgroundJobRunRepository.ListAsync"/>.
/// </summary>
/// <param name="Search">Optional case-insensitive substring match across job_name, operation, error_message.</param>
/// <param name="JobName">Optional exact-match filter on job_name.</param>
/// <param name="Outcome">Optional exact-match filter on outcome.</param>
/// <param name="SortBy">'startedAt' (default) | 'jobName' | 'durationMs' | 'outcome'. Unknown values fall back to 'startedAt'.</param>
/// <param name="SortDir">'asc' or 'desc' (default). Unknown values fall back to 'desc'.</param>
public sealed record BackgroundJobRunQuery(
    string? Search = null,
    string? JobName = null,
    string? Outcome = null,
    string? SortBy = null,
    string? SortDir = null,
    int Limit = 50,
    int Offset = 0);

/// <summary>
/// Persistent log of <see cref="Observability.BackgroundJobScope"/> runs. Replaces the in-memory
/// last-success dictionary on <see cref="Observability.DependablyMeter"/> with a per-run record
/// surfaced in the sysadmin Audit page "Background Jobs" tab. Writes happen fire-and-forget from
/// <see cref="Observability.BackgroundJobScope.Dispose"/>; reads are operator-only.
/// </summary>
public sealed class BackgroundJobRunRepository
{
    private readonly IMetadataStore _db;

    public BackgroundJobRunRepository(IMetadataStore db) => _db = db;

    /// <summary>Insert a single run row. Idempotent on <see cref="BackgroundJobRunRecord.Id"/> (PK conflict swallowed by caller).</summary>
    public async Task RecordAsync(BackgroundJobRunRecord run, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO background_job_runs
                (id, job_name, operation, run_id, started_at, finished_at, duration_ms, outcome, error_message)
            VALUES
                (@id, @jobName, @operation, @runId, @startedAt, @finishedAt, @durationMs, @outcome, @errorMessage)
            """,
            new
            {
                id = run.Id,
                jobName = run.JobName,
                operation = run.Operation,
                runId = run.RunId,
                startedAt = run.StartedAt.UtcDateTime.ToUtcIso(),
                finishedAt = run.FinishedAt.UtcDateTime.ToUtcIso(),
                durationMs = run.DurationMs,
                outcome = run.Outcome,
                errorMessage = run.ErrorMessage,
            });
    }

    /// <summary>
    /// Deletes one bounded batch of aged run rows and returns how many went. Successes age out at
    /// <paramref name="successCutoff"/>, everything else at the later <paramref name="failureCutoff"/> —
    /// a non-success row is the forensic record an operator goes looking for, and there are few of them.
    /// </summary>
    /// <remarks>
    /// <para>Two rows per job are protected regardless of age, because <c>HealthService</c> reads
    /// exactly those: the latest row for each <c>job_name</c>, and the latest <c>success</c> row for
    /// each <c>job_name</c> — the second is its fallback when the latest run is <c>cancelled</c>
    /// (graceful-shutdown disposal mid-tick). Without the success half, retention on a job that has
    /// been idle past the window would empty that fallback and flip a healthy job to unknown.</para>
    /// <para>The caller loops until a batch comes back short. Deleting in batches keyed by the
    /// primary key keeps each statement bounded: SQLite has a single writer, and on Postgres one
    /// year-scale statement means lock duration and bloat.</para>
    /// <para>The table carries no <c>org_id</c>: background jobs are instance-level, so this sweep
    /// is cross-tenant by construction rather than by omission.</para>
    /// </remarks>
    public async Task<int> PruneAsync(
        string successCutoff, string failureCutoff, int batchSize, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM background_job_runs
            WHERE id IN (
                SELECT r.id FROM background_job_runs r
                WHERE ((r.outcome = 'success' AND r.started_at < @successCutoff)
                    OR (r.outcome <> 'success' AND r.started_at < @failureCutoff))
                  AND r.id NOT IN (
                      SELECT b.id FROM background_job_runs b
                      WHERE b.started_at = (
                          SELECT MAX(x.started_at) FROM background_job_runs x
                          WHERE x.job_name = b.job_name)
                      UNION
                      SELECT b.id FROM background_job_runs b
                      WHERE b.outcome = 'success'
                        AND b.started_at = (
                            SELECT MAX(x.started_at) FROM background_job_runs x
                            WHERE x.job_name = b.job_name AND x.outcome = 'success')
                  )
                LIMIT @batchSize
            )
            """,
            new { successCutoff, failureCutoff, batchSize },
            cancellationToken: ct));
    }

    [SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The interpolated whereClause is a const string containing only @param placeholders. " +
                        "ORDER BY column and direction are whitelisted via switch expressions that return " +
                        "compile-time-constant literals (\"job_name\"/\"duration_ms\"/\"outcome\"/\"started_at\") " +
                        "and the literal strings \"ASC\"/\"DESC\"; caller input only selects which constant to use.")]
    public async Task<(IReadOnlyList<BackgroundJobRun> Items, int Total)> ListAsync(
        BackgroundJobRunQuery query, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // ORDER BY is interpolated into the SQL — whitelist before use. Never trust raw input here.
        string orderColumn = query.SortBy switch
        {
            "jobName" => "job_name",
            "durationMs" => "duration_ms",
            "outcome" => "outcome",
            _ => "started_at",
        };
        string orderDirection = string.Equals(query.SortDir, "asc", StringComparison.OrdinalIgnoreCase) ? "ASC" : "DESC";

        string? searchPattern = LikePattern.ContainsLower(query.Search);
        string? jobNameFilter = string.IsNullOrWhiteSpace(query.JobName) ? null : query.JobName;
        string? outcomeFilter = string.IsNullOrWhiteSpace(query.Outcome) ? null : query.Outcome;

        const string whereClause = """
            (@jobName IS NULL OR job_name = @jobName)
              AND (@outcome IS NULL OR outcome = @outcome)
              AND (@searchPattern IS NULL
                   OR lower(job_name) LIKE @searchPattern ESCAPE '\'
                   OR lower(operation) LIKE @searchPattern ESCAPE '\'
                   OR lower(COALESCE(error_message, '')) LIKE @searchPattern ESCAPE '\')
            """;

        // rawsql: whereClause is a const with only @param placeholders (see S2077 justification above).
        int total = await conn.ExecuteScalarAsync<int>(
            $"SELECT COUNT(*) FROM background_job_runs WHERE {whereClause}",
            new { jobName = jobNameFilter, outcome = outcomeFilter, searchPattern });

        // rawsql: only the whitelisted ORDER BY column/direction are interpolated (see S2077 justification above).
        string listSql = $"""
            SELECT id AS Id,
                   job_name AS JobName,
                   operation AS Operation,
                   run_id AS RunId,
                   started_at AS StartedAt,
                   finished_at AS FinishedAt,
                   duration_ms AS DurationMs,
                   outcome AS Outcome,
                   error_message AS ErrorMessage
            FROM background_job_runs
            WHERE {whereClause}
            ORDER BY {orderColumn} {orderDirection}, id DESC
            LIMIT @limit OFFSET @offset
            """;

        var rows = await conn.QueryAsync<BackgroundJobRun>(
            listSql,
            new { limit = query.Limit, offset = query.Offset, jobName = jobNameFilter, outcome = outcomeFilter, searchPattern });
        return (rows.ToList(), total);
    }

    /// <summary>Distinct job_name values for populating the filter dropdown. Sorted alphabetically.</summary>
    public async Task<IReadOnlyList<string>> ListDistinctJobNamesAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<string>(
            "SELECT DISTINCT job_name FROM background_job_runs ORDER BY job_name ASC");
        return rows.ToList();
    }
}
