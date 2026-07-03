using System.Data;
using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure;

/// <summary>
/// Seeds the standard public upstream registries for a newly-created org, and backfills them for
/// existing orgs on upgrade. This preserves the pre-configurable-upstreams behaviour: before this
/// feature every ecosystem proxied through a single hard-coded default, so a fresh org must start
/// with those same defaults as real rows (the proxy now treats "no rows" as "proxying disabled").
///
/// The seed values come from the effective configuration, so a deployment that overrode e.g.
/// <c>PyPI:Upstream</c> keeps its custom mirror as the seeded row. RPM has no hard-coded default
/// (its repos are distro-specific), so it is only seeded when <c>Rpm:Upstream</c> is set.
/// </summary>
public static class UpstreamRegistrySeeder
{
    // (ecosystem, config key, hard-coded fallback URL or null when there is no sensible default).
    private static readonly (string Ecosystem, string ConfigKey, string? Default)[] DefaultSources =
    [
        ("pypi",   "PyPI:Upstream",  "https://pypi.org"),
        ("npm",    "Npm:Upstream",   "https://registry.npmjs.org"),
        ("nuget",  "NuGet:Upstream", "https://api.nuget.org/v3"),
        ("maven",  "Maven:Upstream", "https://repo1.maven.org/maven2"),
        ("golang", "Go:Upstream",    "https://proxy.golang.org"),
        ("rpm",    "Rpm:Upstream",   null),
        // Cargo sparse index. crates.io switched to sparse (https://index.crates.io) as of
        // Rust 1.68. The legacy git index at github.com/rust-lang/crates.io-index is still
        // maintained but clients prefer the sparse protocol; this is the canonical default.
        ("cargo",  "Cargo:Upstream", "https://index.crates.io"),
    ];

    /// <summary>
    /// A default upstream to seed: ecosystem, URL, and optional auth (configured alongside
    /// <c>&lt;Eco&gt;:Upstream</c> as <c>&lt;Eco&gt;:UpstreamAuthType</c> / <c>:UpstreamUsername</c> /
    /// <c>:UpstreamSecret</c>). Anonymous when <see cref="AuthType"/> is null.
    /// </summary>
    public sealed record UpstreamDefault(
        string Ecosystem, string Url, string? AuthType, string? Username, string? Secret);

    /// <summary>The (ecosystem, url) defaults to seed, honouring config overrides; skips ecosystems
    /// with no configured/default URL (i.e. RPM unless <c>Rpm:Upstream</c> is set). URL-only view
    /// used by the on-upgrade backfill, which deliberately seeds anonymous public defaults.</summary>
    public static IReadOnlyList<(string Ecosystem, string Url)> ResolveDefaults(IConfiguration? config) =>
        ResolveDefaultsWithAuth(config).Select(d => (d.Ecosystem, d.Url)).ToList();

    /// <summary>
    /// The defaults to seed including any per-ecosystem auth configured alongside the URL. RPM is
    /// always anonymous (RPM mirrors are public distro repos and the RPM proxy threads no
    /// credentials), so its auth keys are ignored.
    /// </summary>
    public static IReadOnlyList<UpstreamDefault> ResolveDefaultsWithAuth(IConfiguration? config)
    {
        var list = new List<UpstreamDefault>();
        foreach (var (eco, key, def) in DefaultSources)
        {
            string? url = config?[key] ?? def;
            if (string.IsNullOrWhiteSpace(url))
            {
                continue;
            }

            string? Read(string suffix) =>
                string.IsNullOrWhiteSpace(config?[$"{key}{suffix}"]) ? null : config[$"{key}{suffix}"];

            bool authCapable = eco != "rpm";
            string? authType = authCapable ? Read("AuthType")?.Trim().ToLowerInvariant() : null;
            string? username = authCapable ? Read("Username")?.Trim() : null;
            string? secret = authCapable ? Read("Secret") : null;
            list.Add(new UpstreamDefault(eco, url.Trim(), authType, username, secret));
        }
        return list;
    }

    /// <summary>
    /// Inserts the default registries for a single new org, including any per-ecosystem upstream
    /// auth configured alongside the URL. Idempotent via the <c>(org_id, ecosystem, url)</c> unique
    /// constraint, so re-running is harmless. A configured secret is encrypted at rest via
    /// <paramref name="envelope"/>; when a secret is configured but the master key is not, seeding
    /// fails closed (no plaintext secret is ever written).
    /// </summary>
    public static async Task SeedForOrgAsync(
        IDbConnection conn, string orgId, IConfiguration? config,
        EnvelopeProtector? envelope = null, IDbTransaction? tx = null, CancellationToken ct = default)
    {
        foreach (var d in ResolveDefaultsWithAuth(config))
        {
            string? storedSecret = null;
            if (d.Secret is not null)
            {
                if (envelope is null || !envelope.IsConfigured)
                {
                    throw new InvalidOperationException(
                        $"Upstream secret configured for '{d.Ecosystem}' but DEPENDABLY_MASTER_KEY is not set; " +
                        "refusing to seed a plaintext secret.");
                }

                storedSecret = envelope.Protect(d.Secret);
            }

            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, username, secret)
                VALUES (@id, @orgId, @eco, @url, 0, @authType, @username, @secret)
                ON CONFLICT (org_id, ecosystem, url) DO NOTHING
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    eco = d.Ecosystem,
                    url = d.Url,
                    authType = d.AuthType ?? "anonymous",
                    username = d.Username,
                    secret = storedSecret,
                },
                transaction: tx, cancellationToken: ct));
        }

        await SeedOciDefaultsForOrgAsync(conn, orgId, tx, ct);
    }

    /// <summary>
    /// Inserts the two default OCI upstream registries for a new or existing org.
    /// Position 0: MCR (mcr.microsoft.com, anonymous, prefixes dotnet/ and playwright).
    /// Position 1: Docker Hub (registry-1.docker.io, dockerhub_token_exchange, catch-all).
    /// Idempotent via the <c>(org_id, ecosystem, url)</c> unique constraint.
    /// </summary>
    public static async Task SeedOciDefaultsForOrgAsync(
        IDbConnection conn, string orgId, IDbTransaction? tx = null, CancellationToken ct = default)
    {
        // MCR at position 0: matches dotnet/ and playwright prefixes before the Docker Hub catch-all.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, prefixes)
            VALUES (@id, @orgId, 'oci', 'mcr.microsoft.com', 0, 'anonymous', '["dotnet/","playwright"]')
            ON CONFLICT (org_id, ecosystem, url) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId },
            transaction: tx, cancellationToken: ct));

        // Docker Hub at position 1: includes the catch-all prefix "" so any unmatched repository routes here.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, token_endpoint, prefixes)
            VALUES (@id, @orgId, 'oci', 'registry-1.docker.io', 1, 'dockerhub_token_exchange',
                    'https://auth.docker.io/token', '["library/",""]')
            ON CONFLICT (org_id, ecosystem, url) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId },
            transaction: tx, cancellationToken: ct));
    }
}
