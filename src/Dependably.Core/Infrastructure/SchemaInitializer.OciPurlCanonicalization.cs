using System.Data.Common;
using Dapper;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Rewrites stored <c>quarantine.purl</c> values for OCI onto the canonical form
/// <see cref="PurlNormalizer.Oci"/> derives, so a row addresses the artefact the gate addresses.
///
/// <para>The OCI controllers used to build their PURLs by interpolation — <c>pkg:oci/{repository}
/// @{digest}</c> — while every catalogue writer went through <see cref="PurlNormalizer"/>. The
/// interpolated form folds the namespace into the name and leaves the digest's colon unencoded,
/// so it is not a valid PURL and does not match what any other plane records. The write side is
/// fixed; these rows are not, and nothing else rewrites them.</para>
///
/// <para><b>Why the rows matter and history does not.</b> <c>quarantine</c> is read back by
/// <c>HasApprovedForPurlAsync</c> — "an approved review row on the purl is the unblock signal"
/// (<c>BlockGateService</c>). Leave a row on the old spelling and the operator's approval stops
/// being found the moment the gate starts asking under the new one: the image is blocked again
/// while the review UI still renders it as approved, which is precisely the silent failure
/// <c>NormalizeVulnAnalysisPurlKeysAsync</c> exists to undo one table over. <c>activity</c> and
/// <c>audit_log</c> are deliberately left alone — they are append-only history, nothing reads
/// them back by purl to make a decision, and rewriting what an audit row said at the time it was
/// written is worse than leaving it inconsistent.</para>
///
/// <para>Convergent rather than ledgered, for the blue-green reason its siblings give: a slot of
/// the previous release serving against this database still writes the interpolated spelling, so
/// a one-shot recorded as applied would strand every row written during the cutover window. A
/// distinct-purl probe makes the pass free on a database holding none.</para>
///
/// <para><b>Collisions.</b> <c>UNIQUE (org_id, purl)</c> refuses a rewrite that lands on a row
/// already holding the canonical spelling. The survivor is the row readers already resolve to —
/// the canonical one — but it adopts the stale row's decision when it is itself still
/// <c>pending</c> and the stale row was decided. An operator's recorded decision is the one thing
/// in these rows that cannot be reconstructed, so it outranks row identity wherever the two
/// conflict.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    private async Task CanonicalizeOciQuarantinePurlsAsync(DbConnection conn)
    {
        // Distinct purls, not rows: a database whose OCI rows are all canonical does one scan
        // returning a handful of strings and stops. The canonical form is a C# derivation with no
        // SQL equivalent, so the filtering happens here rather than in the predicate. Streamed
        // rather than buffered, so the no-op case costs no memory proportional to the corpus.
        var rewrites = new Dictionary<string, string>(StringComparer.Ordinal);

        // xtenant: instance-wide integrity sweep at schema apply; the rows are per-tenant but the
        // scan that finds them is not, and no tenant context exists at boot.
        await foreach (string stored in conn.QueryUnbufferedAsync<string>(
            "SELECT DISTINCT purl FROM quarantine WHERE ecosystem = 'oci'"))
        {
            if (TryCanonicalizeOciPurl(stored) is { } canonical &&
                !string.Equals(canonical, stored, StringComparison.Ordinal))
            {
                rewrites[stored] = canonical;
            }
        }

        if (rewrites.Count == 0)
        {
            return;
        }

        int rewritten = 0;
        int merged = 0;
        foreach (var (stale, canonical) in rewrites.OrderBy(r => r.Key, StringComparer.Ordinal))
        {
            var (one, collided) = await CanonicalizeOneOciPurlAsync(conn, stale, canonical);
            rewritten += one;
            merged += collided;
        }

        _logger.LogInformation(
            "Rewrote {Rewritten} quarantine row(s) onto the canonical OCI purl the block gate " +
            "derives, across {PurlCount} artefact(s); {Merged} landed on a row that already held " +
            "the canonical spelling and were merged into it, recorded decision first.",
            rewritten, rewrites.Count, merged);
    }

    /// <summary>
    /// The interpolated spelling parsed back into its parts and re-derived. Returns null for
    /// anything that is not the interpolated digest form — an already-canonical purl (it carries
    /// the <c>repository_url</c> qualifier), or a shape this pass does not recognise, both of
    /// which are left exactly as stored rather than guessed at.
    /// </summary>
    internal static string? TryCanonicalizeOciPurl(string stored)
    {
        const string prefix = "pkg:oci/";
        if (!stored.StartsWith(prefix, StringComparison.Ordinal) ||
            stored.Contains("?repository_url=", StringComparison.Ordinal))
        {
            return null;
        }

        // A repository name cannot contain '@' (OCI grammar), and a digest cannot either, so the
        // last '@' is unambiguously the separator. No '@' at all is the tag-coordinate form that
        // only ever reached activity rows — not a digest reference, so not canonicalizable.
        string rest = stored[prefix.Length..];
        int at = rest.LastIndexOf('@');
        if (at <= 0 || at == rest.Length - 1)
        {
            return null;
        }

        string repository = rest[..at];
        string digest = rest[(at + 1)..];
        return digest.Contains(':', StringComparison.Ordinal)
            ? PurlNormalizer.Oci(repository, digest)
            : null;
    }

    private static async Task<(int Rewritten, int Merged)> CanonicalizeOneOciPurlAsync(
        DbConnection conn, string stale, string canonical)
    {
        // Both spellings in one read so a collision is decided from the rows themselves rather
        // than from a failed insert. UNIQUE (org_id, purl) bounds each org at one row per
        // spelling.
        // xtenant: same instance-wide sweep; every statement below is scoped by the row's own
        // org_id, which is read here.
        var rows = (await conn.QueryAsync<QuarantinePurlRow>(new CommandDefinition(
            """
            SELECT org_id AS OrgId, purl AS Purl, state AS State
            FROM quarantine
            WHERE purl IN (@stale, @canonical)
            """,
            new { stale, canonical }))).ToList();

        int rewritten = 0;
        int merged = 0;
        foreach (var group in rows.GroupBy(r => r.OrgId, StringComparer.Ordinal))
        {
            var staleRow = group.FirstOrDefault(r => string.Equals(r.Purl, stale, StringComparison.Ordinal));
            if (staleRow is null)
            {
                continue;
            }

            var canonicalRow = group.FirstOrDefault(r => string.Equals(r.Purl, canonical, StringComparison.Ordinal));
            if (canonicalRow is null)
            {
                // No collision: the rename is the whole repair.
                // xtenant: scoped by this row's own org_id.
                rewritten += await conn.ExecuteAsync(new CommandDefinition(
                    "UPDATE quarantine SET purl = @canonical WHERE org_id = @orgId AND purl = @stale",
                    new { canonical, orgId = group.Key, stale }));
                continue;
            }

            // Collision. The canonical row survives because it is the one readers resolve to, but
            // a decision recorded on the stale row is not reconstructible and must not be lost to
            // that choice.
            if (string.Equals(canonicalRow.State, "pending", StringComparison.Ordinal) &&
                !string.Equals(staleRow.State, "pending", StringComparison.Ordinal))
            {
                // xtenant: scoped by this row's own org_id.
                await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE quarantine
                    SET state = (SELECT state FROM quarantine WHERE org_id = @orgId AND purl = @stale),
                        decided_by = (SELECT decided_by FROM quarantine WHERE org_id = @orgId AND purl = @stale),
                        decided_at = (SELECT decided_at FROM quarantine WHERE org_id = @orgId AND purl = @stale),
                        note = (SELECT note FROM quarantine WHERE org_id = @orgId AND purl = @stale)
                    WHERE org_id = @orgId AND purl = @canonical
                    """,
                    new { orgId = group.Key, stale, canonical }));
            }

            // xtenant: scoped by this row's own org_id.
            await conn.ExecuteAsync(new CommandDefinition(
                "DELETE FROM quarantine WHERE org_id = @orgId AND purl = @stale",
                new { orgId = group.Key, stale }));
            merged++;
        }

        return (rewritten, merged);
    }

    /// <summary>One quarantine row's identity and decision state, for the collision merge.</summary>
    private sealed record QuarantinePurlRow(string OrgId, string Purl, string State);
}
