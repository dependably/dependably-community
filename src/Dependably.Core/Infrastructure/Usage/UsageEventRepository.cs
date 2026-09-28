using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure.Usage;

/// <summary>
/// Writes and ages out the raw metering record in <c>usage_events</c>. The table is append-only:
/// nothing here updates a row, and the only delete is the fixed-horizon retention sweep.
/// </summary>
public sealed class UsageEventRepository
{
    private const string InsertEventSql =
        """
        INSERT INTO usage_events (event_id, org_id, meter, delivery, quantity, source, object_ref, occurred_at)
        VALUES (@EventId, @OrgId, @Meter, @Delivery, @Quantity, @Source, @ObjectRef, @OccurredAt)
        ON CONFLICT (event_id) DO NOTHING
        """;

    private readonly IMetadataStore _db;

    public UsageEventRepository(IMetadataStore db) => _db = db;

    /// <summary>
    /// Inserts a batch in one transaction. An event whose id is already stored is skipped, so
    /// retrying a batch after a failure that may or may not have committed never double-counts.
    /// </summary>
    public async Task InsertBatchAsync(IReadOnlyList<UsageEvent> events, CancellationToken ct = default)
    {
        if (events.Count == 0)
        {
            return;
        }

        // xtenant: one batch carries events for many orgs, each row naming its own org_id.
        await using var conn = await _db.OpenCrossTenantAsync("usage event batch", ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        if (_db.Provider == DbProvider.Postgres)
        {
            // Npgsql pipelines a DbBatch into one round-trip. The command text is a constant
            // parameterized INSERT; no SQL is built from event data.
            await using var batch = conn.CreateBatch();
            batch.Transaction = tx;
            foreach (var e in events)
            {
                var cmd = batch.CreateBatchCommand();
                cmd.CommandText = InsertEventSql;
                AddParameter(cmd, "@EventId", e.EventId);
                AddParameter(cmd, "@OrgId", e.OrgId);
                AddParameter(cmd, "@Meter", e.Meter);
                AddParameter(cmd, "@Delivery", e.Delivery);
                AddParameter(cmd, "@Quantity", e.Quantity);
                AddParameter(cmd, "@Source", e.Source);
                AddParameter(cmd, "@ObjectRef", e.ObjectRef);
                AddParameter(cmd, "@OccurredAt", e.OccurredAt);
                batch.BatchCommands.Add(cmd);
            }

            await batch.ExecuteNonQueryAsync(ct);
        }
        else
        {
            // Microsoft.Data.Sqlite has no DbBatch; Dapper runs the command once per row inside
            // the one transaction, so the commit is still paid once per batch.
            await conn.ExecuteAsync(InsertEventSql, events, transaction: tx);
        }

        await tx.CommitAsync(ct);
    }

    /// <summary>
    /// Deletes every event that occurred before <paramref name="cutoff"/>, across every org.
    /// </summary>
    public async Task<int> PruneOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        string cutoffIso = cutoff.ToUtcIsoMillis();
        // xtenant: an instance-wide retention sweep at a fixed horizon.
        await using var conn = await _db.OpenCrossTenantAsync("usage event retention", ct);
        // xtenant: instance-wide retention sweep at a fixed horizon that no tenant controls; the
        // same posture as the other age-based sweeps in RetentionService.
        return await conn.ExecuteAsync(
            "DELETE FROM usage_events WHERE occurred_at < @cutoffIso",
            new { cutoffIso });
    }

    private static void AddParameter(DbBatchCommand cmd, string name, object? value)
    {
        var p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value ?? DBNull.Value;
        cmd.Parameters.Add(p);
    }
}
