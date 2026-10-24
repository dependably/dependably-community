using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Records how long each connection to the shared in-memory test database holds a write
/// transaction, which tables it wrote, and who ran it, so a slow flush can name the lock holder
/// instead of only timing out.
///
/// <para>
/// A shared-cache database allows one write transaction at a time and ignores
/// <c>busy_timeout</c>, so a blocked write waits out the driver's command timeout rather than
/// the PRAGMA. A write transaction is measured from the first row it changes to its commit or
/// rollback. Locks that are held without a write — a read transaction left open, a statement
/// stepped but never reset — are not hooked; <see cref="Report"/> lists the connections that are
/// inside a transaction at the moment it is called.
/// </para>
///
/// <para>
/// The owner is the nearest Dependably frames on the stack when the first row changed, plus the
/// ambient request activity when there is one. A statement started after an await resumes on a
/// pool thread, so the stack shows the repository method rather than the hosted service that
/// called it; the repository name is what identifies the holder.
/// </para>
/// </summary>
public sealed class SqliteLockDiagnostics
{
    /// <summary>A write transaction held longer than this is kept in the report.</summary>
    public static readonly TimeSpan HoldThreshold = TimeSpan.FromMilliseconds(100);

    private const int MaxRecords = 500;

    private readonly ConcurrentDictionary<long, ConnectionState> _connections = new();
    private readonly ConcurrentQueue<Hold> _holds = new();
    private long _nextConnectionId;
    private long _writeTransactions;

    public long WriteTransactionCount => Interlocked.Read(ref _writeTransactions);

    /// <summary>The longest write-transaction holds recorded so far, longest first.</summary>
    public IReadOnlyList<(TimeSpan Duration, string Owner, string Tables)> Longest(int count) =>
        _holds.OrderByDescending(h => h.Duration).Take(count).Select(h => (h.Duration, h.Owner, h.Tables)).ToList();

    /// <summary>Starts recording write transactions on <paramref name="connection"/>. Call once, after it is open.</summary>
    public void Attach(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        long id = Interlocked.Increment(ref _nextConnectionId);
        var state = new ConnectionState(id, connection.Handle!);
        _connections[id] = state;

        var db = connection.Handle!;
        raw.sqlite3_update_hook(db, (_, _, _, table, _) =>
        {
            string name = table.utf8_to_string();
            Safely(() => OnWrite(state, name));
        }, null);
        raw.sqlite3_commit_hook(db, _ =>
        {
            Safely(() => OnEnd(state));
            return 0;
        }, null);
        raw.sqlite3_rollback_hook(db, _ => Safely(() => OnEnd(state)), null);
        connection.StateChange += (sender, e) =>
        {
            if (e.CurrentState == System.Data.ConnectionState.Closed)
            {
                OnEnd(state);
                _connections.TryRemove(id, out _);
            }
        };
    }

    /// <summary>Records the owner of a transaction begun through the connection, for the open-transaction listing.</summary>
    public void NoteBegin(SqliteConnection connection)
    {
        foreach (var state in _connections.Values)
        {
            if (ReferenceEquals(state.Handle, connection.Handle))
            {
                // now-ok: native lock hold time, diagnostic only.
                state.Begun = new Started(Stopwatch.GetTimestamp(), CaptureOwner(), "");
                return;
            }
        }
    }

    /// <summary>
    /// Connections that are inside a transaction right now (past <paramref name="minAge"/> if it
    /// has written), and the longest write-transaction holds seen so far, as text for test output.
    /// </summary>
    public string Report(TimeSpan minAge)
    {
        // now-ok: measures real elapsed time of a native lock for a diagnostic report; nothing branches on it.
        long now = Stopwatch.GetTimestamp();
        var text = new StringBuilder();
        var longest = Longest(1);
        text.AppendLine(
            $"sqlite lock diagnostics: {WriteTransactionCount} write transactions, " +
            (longest.Count == 0
                ? "none held for the threshold"
                : $"longest {longest[0].Duration.TotalMilliseconds:F0} ms ({longest[0].Owner}; {longest[0].Tables})"));

        // A flush that is slow with no lock held anywhere points at the process being starved —
        // a deep thread-pool queue or a saturated CPU — rather than at a lock.
        text.AppendLine(
            $"  thread pool: {ThreadPool.ThreadCount} threads, {ThreadPool.PendingWorkItemCount} queued work items, " +
            $"{Environment.ProcessorCount} processors");

        int open = 0;
        foreach (var state in _connections.Values)
        {
            if (raw.sqlite3_get_autocommit(state.Handle) != 0)
            {
                continue;
            }

            var write = state.Write;
            var begun = state.Begun;
            if (write is { } w)
            {
                var age = Stopwatch.GetElapsedTime(w.Timestamp, now);
                if (age >= minAge)
                {
                    open++;
                    text.AppendLine($"  OPEN WRITE TRANSACTION conn#{state.Id} for {age.TotalMilliseconds:F0} ms, tables {w.Tables}, owner {w.Owner}");
                }
            }
            else if (begun is { } b)
            {
                open++;
                text.AppendLine($"  OPEN TRANSACTION (no write yet) conn#{state.Id} for {Stopwatch.GetElapsedTime(b.Timestamp, now).TotalMilliseconds:F0} ms, owner {b.Owner}");
            }
            else
            {
                open++;
                text.AppendLine($"  OPEN TRANSACTION conn#{state.Id}, begun outside the tracked connection");
            }
        }

        if (open == 0)
        {
            text.AppendLine("  no connection is inside a transaction right now");
        }

        foreach (var hold in _holds.OrderByDescending(h => h.Duration).Take(10))
        {
            text.AppendLine(
                $"  write transaction conn#{hold.ConnectionId} held {hold.Duration.TotalMilliseconds:F0} ms, tables {hold.Tables}, owner {hold.Owner}");
        }

        return text.ToString();
    }

    private static void OnWrite(ConnectionState state, string table)
    {
        lock (state)
        {
            if (state.Write is { } started)
            {
                if (!started.Tables.Contains(table, StringComparison.Ordinal))
                {
                    state.Write = started with { Tables = started.Tables + "," + table };
                }

                return;
            }

            // now-ok: native lock hold time, diagnostic only.
            state.Write = new Started(Stopwatch.GetTimestamp(), CaptureOwner(), table);
        }
    }

    private void OnEnd(ConnectionState state)
    {
        Started? write;
        lock (state)
        {
            write = state.Write;
            state.Write = null;
            state.Begun = null;
        }

        if (write is not { } w)
        {
            return;
        }

        Interlocked.Increment(ref _writeTransactions);
        // now-ok: native lock hold time, diagnostic only.
        var held = Stopwatch.GetElapsedTime(w.Timestamp);
        if (held >= HoldThreshold)
        {
            _holds.Enqueue(new Hold(state.Id, held, w.Tables, w.Owner));
            while (_holds.Count > MaxRecords && _holds.TryDequeue(out _))
            {
            }
        }
    }

    private static string CaptureOwner()
    {
        var names = new List<string>(3);
        foreach (var frame in new StackTrace(false).GetFrames())
        {
            var method = frame.GetMethod();
            var type = method?.DeclaringType;
            string? ns = type?.Namespace;
            if (type is null || method is null || ns is null || !ns.StartsWith("Dependably", StringComparison.Ordinal)
                || type.FullName!.StartsWith(typeof(SqliteLockDiagnostics).FullName!, StringComparison.Ordinal)
                || type.Name == nameof(TrackedSqliteConnection))
            {
                continue;
            }

            // An async state machine is a nested type named <Method>d__N; report the method.
            string name = type.DeclaringType is { } outer && type.Name.StartsWith('<')
                ? $"{outer.Name}.{type.Name[1..type.Name.IndexOf('>')]}"
                : $"{type.Name}.{method.Name}";
            if (!names.Contains(name))
            {
                names.Add(name);
            }

            if (names.Count == 3)
            {
                break;
            }
        }

        string? request = Activity.Current?.DisplayName;
        string frames = names.Count == 0 ? "no Dependably frame" : string.Join(" < ", names);
        return request is null ? frames : $"{frames} [request {request}]";
    }

    // A native callback must never throw into SQLite.
    private static void Safely(Action action)
    {
        try
        {
            action();
        }
        catch (Exception)
        {
            // Diagnostics only.
        }
    }

    private readonly record struct Started(long Timestamp, string Owner, string Tables);

    private readonly record struct Hold(long ConnectionId, TimeSpan Duration, string Tables, string Owner);

    private sealed class ConnectionState(long id, sqlite3 handle)
    {
        public long Id { get; } = id;

        public sqlite3 Handle { get; } = handle;

        public Started? Write { get; set; }

        public Started? Begun { get; set; }
    }
}

/// <summary>
/// A connection that tells <see cref="SqliteLockDiagnostics"/> who began each transaction.
/// </summary>
internal sealed class TrackedSqliteConnection(string connectionString, SqliteLockDiagnostics diagnostics)
    : SqliteConnection(connectionString)
{
    protected override System.Data.Common.DbTransaction BeginDbTransaction(System.Data.IsolationLevel isolationLevel)
    {
        var transaction = base.BeginDbTransaction(isolationLevel);
        diagnostics.NoteBegin(this);
        return transaction;
    }
}
