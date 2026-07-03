using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Records and enforces per-(org, ecosystem, package-name) upstream source pins. The first
/// upstream to successfully serve a proxied name binds that name to that upstream host; a
/// subsequent proxy fetch that resolves the same name from a DIFFERENT upstream host is refused.
///
/// This is the non-OCI analogue of OCI repository-prefix routing (OciUpstreamResolver). It closes
/// the dependency-confusion window where a private upstream's miss (down, transient 404, version
/// not yet published) silently falls through to a lower-priority public upstream squatting the
/// same name.
///
/// Enforcement is opt-in (off by default) so it never surprises an existing multi-mirror
/// deployment or blocks proxying after an operator legitimately re-points an upstream host.
/// Set <c>PROXY_SOURCE_PINNING=true</c> (or <c>Proxy:SourcePinning=true</c>) to pin each
/// (org, ecosystem, name) to its first-serving upstream host and refuse a later serve from a
/// different host.
/// </summary>
public sealed class SourcePinRepository
{
    private readonly IMetadataStore _db;

    public SourcePinRepository(IMetadataStore db, IConfiguration config)
    {
        _db = db;
        string? raw = config["PROXY_SOURCE_PINNING"] ?? config["Proxy:SourcePinning"];
        Enabled = string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) || raw == "1";
    }

    /// <summary>Whether source-pin enforcement is active for this instance.</summary>
    public bool Enabled { get; }

    /// <summary>
    /// The upstream host this (org, ecosystem, name) is pinned to, or null when it is not yet
    /// pinned.
    /// </summary>
    public async Task<string?> GetPinnedHostAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT upstream_host FROM upstream_source_pin
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND name = @name
            """,
            new { orgId, ecosystem, name });
    }

    /// <summary>
    /// Pins the name to <paramref name="host"/> when it is not already pinned (first-serve wins),
    /// then returns the winning host — the pre-existing pin when a concurrent first-fetch from a
    /// different upstream won the race. The caller compares the returned host against the one it
    /// served from and refuses the fetch on mismatch.
    /// </summary>
    public async Task<string> PinIfAbsentAsync(
        string orgId, string ecosystem, string name, string host, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_source_pin (org_id, ecosystem, name, upstream_host)
            VALUES (@orgId, @ecosystem, @name, @host)
            ON CONFLICT (org_id, ecosystem, name) DO NOTHING
            """,
            new { orgId, ecosystem, name, host });

        // The row exists after the INSERT/ON-CONFLICT above; fall back to the just-served host if
        // a concurrent delete removed it (treated as a match so the current serve proceeds).
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT upstream_host FROM upstream_source_pin
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND name = @name
            """,
            new { orgId, ecosystem, name }) ?? host;
    }
}
