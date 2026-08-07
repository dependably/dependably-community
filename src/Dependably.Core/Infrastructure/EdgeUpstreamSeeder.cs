using System.Data;
using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure;

/// <summary>
/// Seeds the single-upstream registry rows for a headless edge node: one
/// <c>upstream_registry</c> row per ecosystem pointing at the central master
/// (<c>EDGE_MASTER_URL</c> + that ecosystem's canonical prefix), plus one OCI row for the
/// master host. Every row carries the edge's reader token (<c>EDGE_MASTER_TOKEN</c>) so the
/// pull-through fetch authenticates to the master, encrypted at rest via the same
/// <see cref="EnvelopeProtector"/> path as any other upstream secret.
///
/// The resolver is deliberately DB-only, so edge single-upstream resolution is expressed as
/// real seeded rows rather than a config-reading resolver branch — the resolver contract stays
/// intact. In edge mode these rows REPLACE the standard public-registry defaults; the public
/// seeds are not written.
///
/// Seeding is re-run on every boot and is deterministic: it deletes the org's existing rows
/// and reinserts the current master rows, so a changed <c>EDGE_MASTER_URL</c> or
/// <c>EDGE_MASTER_TOKEN</c> propagates on the next start (a URL change is part of the
/// <c>UNIQUE(org_id, ecosystem, url)</c> key, which a plain upsert could not reconcile). An
/// edge org holds only edge rows, so the delete-and-reinsert is scoped safely to it.
/// </summary>
public static class EdgeUpstreamSeeder
{
    // (ecosystem, path suffix appended to EDGE_MASTER_URL). Each base URL is the exact shape the
    // matching proxy fetcher expects to append ecosystem-specific paths to:
    //   pypi   — fetcher appends "/simple/{pkg}/" and "/pypi/{name}/{version}/json"; master serves
    //            both at the root host, so the base is the bare master URL.
    //   npm    — fetcher appends "/{pkg}" (packument) and "/{pkg}/-/{file}" (tarball); master npm
    //            surface is under /npm.
    //   nuget  — fetcher appends "/flatcontainer/..." and "/{registrationVariant}/..."; master
    //            NuGet v3 surface is under /nuget.
    //   maven  — fetcher appends "/{groupPath}/{artifact}/..."; master Maven repo base is /maven.
    //   rpm    — fetcher appends "/repodata/..." and "/Packages/..."; master RPM surface is /rpm.
    //   golang — fetcher appends "/{module}/@v/..."; master Go module proxy is under /go.
    //   cargo  — fetcher appends "/{indexPath}" and (download) "/api/v1/crates/..."; master Cargo
    //            surface is under /cargo. The crates.io static-CDN special-case does not trigger
    //            because the base is not index.crates.io.
    //   apk    — fetcher appends "/{release}/{repo}/{arch}/{file}" verbatim (1:1 with dl-cdn's
    //            layout); master apk surface is under /apk.
    //   terraform — the one row that also pins a protocol. Every other ecosystem works because the
    //            master serves the same protocol its fetcher speaks, so an edge can point at the
    //            master exactly as it would point at the public upstream. Terraform is the one
    //            place those differ: the master serves the *network mirror* protocol at /terraform,
    //            while the fetcher's default is the *registry* protocol ({base}/v1/providers/...).
    //            The row therefore carries upstream_protocol='mirror', which switches the fetcher
    //            to the endpoint shape the master actually serves. Without it every provider fetch
    //            would 404 against a master that is working correctly.
    private static readonly (string Ecosystem, string PathSuffix, string? Protocol)[] NonOciPrefixes =
    [
        ("pypi",      "",           null),
        ("npm",       "/npm",       null),
        ("nuget",     "/nuget",     null),
        ("maven",     "/maven",     null),
        ("rpm",       "/rpm",       null),
        ("golang",    "/go",        null),
        ("cargo",     "/cargo",     null),
        ("apk",       "/apk",       null),
        ("terraform", "/terraform", UpstreamRegistryRepository.MirrorProtocol),
    ];

    /// <summary>
    /// The (ecosystem, url, protocol) rows seeded for an edge node given a master base URL, in the
    /// order they are inserted. Protocol is null for every ecosystem whose serve and fetch
    /// protocols coincide. Exposed for tests to assert the exact prefix table without a DB.
    /// </summary>
    public static IReadOnlyList<(string Ecosystem, string Url, string? Protocol)> ResolveRows(string masterUrl)
    {
        string baseUrl = masterUrl.TrimEnd('/');
        return NonOciPrefixes.Select(p => (p.Ecosystem, baseUrl + p.PathSuffix, p.Protocol)).ToList();
    }

    /// <summary>
    /// The OCI upstream host derived from the master URL (host only, no path — the OCI
    /// Distribution Spec mandates <c>/v2/</c> at the host root). Null when the URL has no host.
    /// </summary>
    public static string? ResolveOciHost(string masterUrl) =>
        Uri.TryCreate(masterUrl.TrimEnd('/'), UriKind.Absolute, out var uri) ? uri.Host : null;

    /// <summary>
    /// Deletes the org's existing upstream rows and reinserts one per ecosystem pointing at the
    /// master, each authenticated with the edge reader token. Idempotent: re-running produces the
    /// same rows; a changed master URL/token yields updated rows. The token is encrypted at rest
    /// via <paramref name="envelope"/>; when a token is present but the master key is not, the
    /// secret is stored as plaintext-passthrough only when the envelope is unconfigured (matching
    /// the rest of the upstream-secret path, which fails closed on Protect without a key). Callers
    /// in edge mode always run with a configured envelope in production.
    /// </summary>
    public static async Task SeedForEdgeAsync(
        IDbConnection conn, string orgId, string masterUrl, string masterToken,
        EnvelopeProtector envelope, IDbTransaction? tx = null, CancellationToken ct = default)
    {
        // Bearer token authenticates to the master for every non-OCI ecosystem: the master's
        // ResolveTokenAsync accepts Bearer on all protocol endpoints, so one scheme covers all.
        string? nonOciSecret = BuildStoredSecret(masterToken, envelope);

        // Wipe the org's rows so a changed master URL (part of the UNIQUE key) cannot leave a
        // stale row behind. An edge org holds only edge rows, so this is scoped safely.
        await conn.ExecuteAsync(new CommandDefinition(
            "DELETE FROM upstream_registry WHERE org_id = @orgId",
            new { orgId }, transaction: tx, cancellationToken: ct));

        foreach (var (ecosystem, url, protocol) in ResolveRows(masterUrl))
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO upstream_registry
                    (id, org_id, ecosystem, url, position, auth_type, username, secret, upstream_protocol)
                VALUES (@id, @orgId, @eco, @url, 0, @authType, NULL, @secret, @protocol)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    eco = ecosystem,
                    url,
                    authType = nonOciSecret is null ? "anonymous" : "bearer",
                    secret = nonOciSecret,
                    protocol,
                },
                transaction: tx, cancellationToken: ct));
        }

        string? ociHost = ResolveOciHost(masterUrl);
        if (ociHost is not null)
        {
            // OCI upstream auth is a distinct scheme set; the master's /v2/ accepts Basic
            // (user:token, username ignored on resolution), so the OCI row uses Basic with the
            // edge token as the password and a catch-all "" prefix so every repository routes here.
            string? ociSecret = BuildStoredSecret(masterToken, envelope);
            await conn.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO upstream_registry (id, org_id, ecosystem, url, position, auth_type, username, secret, prefixes)
                VALUES (@id, @orgId, 'oci', @host, 0, @authType, @username, @secret, '[""]')
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    host = ociHost,
                    authType = ociSecret is null ? "anonymous" : "basic",
                    username = ociSecret is null ? null : "edge",
                    secret = ociSecret,
                },
                transaction: tx, cancellationToken: ct));
        }
    }

    private static string? BuildStoredSecret(string masterToken, EnvelopeProtector envelope)
    {
        if (string.IsNullOrEmpty(masterToken))
        {
            return null;
        }

        // Encrypt at rest when a master key is configured; otherwise store as-is (the read path
        // passes plaintext through the enc:v1: discriminator). Edge mode always ships a token.
        return envelope.IsConfigured ? envelope.Protect(masterToken) : masterToken;
    }
}
