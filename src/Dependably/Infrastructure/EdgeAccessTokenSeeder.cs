using System.Data;
using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Seeds the headless edge node's INBOUND client auth from <c>EDGE_ACCESS_TOKEN</c>.
///
/// When the env var is set, the token is seeded as a real reader-scoped <c>service_tokens</c>
/// row (SHA-256 hash, <see cref="Capabilities.ReaderCapsCanonicalJson"/> capabilities) in the
/// edge's own DB, so <c>TokenAuthExtensions.ResolveTokenAsync</c> plus the existing capability
/// and audit machinery authenticate edge clients with ZERO new auth code paths. The edge org's
/// <c>anonymous_pull</c> is turned OFF so a token is required.
///
/// When the env var is NOT set, the node runs in anonymous mode: the edge org's
/// <c>anonymous_pull</c> is turned ON (reusing the existing org-settings switch) and a single
/// startup warning is emitted — "an edge accepting anonymous clients is intended for trusted
/// networks only".
///
/// Seeding is deterministic and idempotent, mirroring the upstream reseed: the edge's existing
/// seeded access-token row is deleted by its well-known <see cref="TokenDescription"/> marker and
/// reinserted, so rotating <c>EDGE_ACCESS_TOKEN</c> replaces the row on the next boot. The token
/// value is never logged.
/// </summary>
public static class EdgeAccessTokenSeeder
{
    /// <summary>
    /// The description marker on the seeded row. Used both as the human-readable label in the
    /// audit UI and as the deterministic delete key so a rotated token replaces exactly its own
    /// row without touching any other service token an operator may have minted.
    /// </summary>
    public const string TokenDescription = "edge access token (seeded from EDGE_ACCESS_TOKEN)";

    /// <summary>Stable service-token <c>name</c> for the seeded row (audit identifier).</summary>
    public const string TokenName = "edge-access";

    /// <summary>
    /// Applies the edge inbound-auth configuration to <paramref name="orgId"/>. Returns
    /// <see cref="SeedOutcome.Tokened"/> when a token was seeded and anonymous pull disabled, or
    /// <see cref="SeedOutcome.Anonymous"/> when no token was configured and anonymous pull enabled.
    /// The caller emits the anonymous-mode startup warning on <see cref="SeedOutcome.Anonymous"/>.
    /// </summary>
    public static async Task<SeedOutcome> SeedForEdgeAsync(
        IDbConnection conn, string orgId, string? accessToken,
        IDbTransaction? tx = null, CancellationToken ct = default)
    {
        // Always remove any previously-seeded edge access-token row first (keyed on the marker so
        // only this seeder's row is affected). This makes rotation and the token→anonymous
        // transition both deterministic: the old credential stops working on the next boot.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM service_tokens WHERE org_id = @orgId AND description = @desc",
            new { orgId, desc = TokenDescription }, transaction: tx, cancellationToken: ct));

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            // Anonymous mode: reuse the existing org-settings switch rather than new gating.
            await conn.ExecuteAsync(new CommandDefinition(
                "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = @orgId",
                new { orgId }, transaction: tx, cancellationToken: ct));
            return SeedOutcome.Anonymous;
        }

        string tokenHash = TokenRepository.HashToken(accessToken.Trim());
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO service_tokens (id, org_id, name, token_hash, capabilities, description)
            VALUES (@id, @orgId, @name, @hash, @caps, @desc)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                name = TokenName,
                hash = tokenHash,
                caps = Capabilities.ReaderCapsCanonicalJson,
                desc = TokenDescription,
            },
            transaction: tx, cancellationToken: ct));

        // A pre-shared token gates inbound access — anonymous pull must be OFF.
        await conn.ExecuteAsync(new CommandDefinition(
            "UPDATE org_settings SET anonymous_pull = 0 WHERE org_id = @orgId",
            new { orgId }, transaction: tx, cancellationToken: ct));

        return SeedOutcome.Tokened;
    }

    /// <summary>Result of an edge access-token seed pass.</summary>
    public enum SeedOutcome
    {
        /// <summary>A reader token was seeded; anonymous pull is disabled.</summary>
        Tokened,

        /// <summary>No token configured; anonymous pull is enabled (trusted-network mode).</summary>
        Anonymous,
    }
}
