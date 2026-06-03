using System.Data;
using Dapper;

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
        ("pypi",  "PyPI:Upstream",  "https://pypi.org"),
        ("npm",   "Npm:Upstream",   "https://registry.npmjs.org"),
        ("nuget", "NuGet:Upstream", "https://api.nuget.org/v3"),
        ("maven", "Maven:Upstream", "https://repo1.maven.org/maven2"),
        ("rpm",   "Rpm:Upstream",   null),
    ];

    /// <summary>The (ecosystem, url) defaults to seed, honouring config overrides; skips ecosystems
    /// with no configured/default URL (i.e. RPM unless <c>Rpm:Upstream</c> is set).</summary>
    public static IReadOnlyList<(string Ecosystem, string Url)> ResolveDefaults(IConfiguration? config)
    {
        var list = new List<(string, string)>();
        foreach (var (eco, key, def) in DefaultSources)
        {
            var url = config?[key] ?? def;
            if (!string.IsNullOrWhiteSpace(url))
                list.Add((eco, url.Trim()));
        }
        return list;
    }

    /// <summary>Inserts the default registries for a single new org. Idempotent via the
    /// <c>(org_id, ecosystem, url)</c> unique constraint, so re-running is harmless.</summary>
    public static async Task SeedForOrgAsync(
        IDbConnection conn, string orgId, IConfiguration? config, IDbTransaction? tx = null, CancellationToken ct = default)
    {
        foreach (var (eco, url) in ResolveDefaults(config))
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position)
                VALUES (@id, @orgId, @eco, @url, 0)
                ON CONFLICT (org_id, ecosystem, url) DO NOTHING
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, eco, url },
                transaction: tx, cancellationToken: ct));
        }
    }
}
