using System.Net;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using Xunit.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Measures what Postgres row-level security costs on the serve path, on a skewed fixture: one large
/// tenant (the one served) beside several small ones, so the planner sees realistic statistics. Two
/// paths — a proxied NuGet package already in the cache, and a hosted npm tarball — are timed over
/// sequential requests under three stacks: RLS off, RLS enforced, and RLS enforced plus a trial
/// <c>EXISTS</c>-through-<c>packages</c> policy on <c>package_versions</c>, the candidate for
/// covering the version-scoped tables.
///
/// <para>A measurement, not a gate: it asserts only that every request succeeded, and reports
/// p50/p99 through the test output. Excluded from the CI integration jobs by its
/// <c>Category=Benchmark</c> trait; run it with
/// <c>dotnet test --filter "Category=Benchmark"</c> and <c>TEST_POSTGRES_CONNECTION</c> set.</para>
/// </summary>
[Trait("Category", "Integration")]
[Trait("Category", "Benchmark")]
public sealed class RowLevelSecurityServePathBenchmark(ITestOutputHelper output)
{
    private const int Warmup = 100;
    private const int Samples = 1000;
    private const string NuGetId = "bench.proxied";
    private const string NpmName = "bench-hosted";

    [Fact]
    public async Task ServePath_LatencyWithAndWithoutRowLevelSecurity()
    {
        var stacks = new (string Label, string Database, bool VersionPolicy)[]
        {
            ("rls off", "postgres", false),
            ("rls enforce", "postgres-rls", false),
            ("rls enforce + package_versions EXISTS policy", "postgres-rls", true),
        };

        foreach (var (label, database, versionPolicy) in stacks)
        {
            await using var factory = new DependablyFactory { Database = database };
            string token = await factory.CreateToken("push");
            await SeedSkewAsync(factory);
            await PrimeProxiedPackageAsync(factory, token);
            await PublishHostedPackageAsync(factory, token);
            if (versionPolicy)
            {
                await AddVersionPolicyAsync(factory);
            }

            await AnalyzeAsync(factory);

            using var client = factory.CreateClientWithBearer(token);
            var (proxiedP50, proxiedP99) = await TimeAsync(client, $"/nuget/flatcontainer/{NuGetId}/1.0.0/{NuGetId}.1.0.0.nupkg");
            var (hostedP50, hostedP99) = await TimeAsync(client, $"/npm/{NpmName}/-/{NpmName}-1.0.0.tgz");

            output.WriteLine(
                $"{label,-46} proxied cache hit p50={proxiedP50,6:F2}ms p99={proxiedP99,6:F2}ms | " +
                $"hosted download p50={hostedP50,6:F2}ms p99={hostedP99,6:F2}ms");
        }
    }

    private static async Task<(double P50, double P99)> TimeAsync(HttpClient client, string path)
    {
        var samples = new List<double>(Samples);
        for (int i = 0; i < Warmup + Samples; i++)
        {
            long start = TimeProvider.System.GetTimestamp();
            using var resp = await client.GetAsync(path);
            _ = await resp.Content.ReadAsByteArrayAsync();
            double ms = TimeProvider.System.GetElapsedTime(start).TotalMilliseconds;
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            if (i >= Warmup)
            {
                samples.Add(ms);
            }
        }

        samples.Sort();
        return (samples[samples.Count / 2], samples[(int)(samples.Count * 0.99)]);
    }

    // One large tenant — the default org the host serves — and five small ones.
    private static async Task SeedSkewAsync(DependablyFactory factory)
    {
        await using var conn = await factory.Services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("benchmark: skewed fixture");
        string defaultOrg = (await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default'"))!;
        await conn.ExecuteAsync(
            """
            INSERT INTO orgs (id, slug) SELECT 'bench-small-' || g, 'bench-small-' || g FROM generate_series(1, 5) g;

            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
            SELECT 'bench-ca-' || g, 'npm', 'bench-dep-' || g, '1.0.0', 'bench-dep-' || g || '-1.0.0.tgz', 'k-' || g, 'h-' || g
            FROM generate_series(1, 20000) g;

            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id)
            SELECT @defaultOrg, 'bench-ca-' || g FROM generate_series(1, 20000) g;
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id)
            SELECT 'bench-small-' || o, 'bench-ca-' || g FROM generate_series(1, 5) o, generate_series(1, 200) g;

            INSERT INTO packages (id, org_id, ecosystem, name, purl_name)
            SELECT 'bench-pkg-' || g, @defaultOrg, 'npm', 'bench-lib-' || g, 'bench-lib-' || g FROM generate_series(1, 5000) g;
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name)
            SELECT 'bench-pkg-' || o || '-' || g, 'bench-small-' || o, 'npm', 'bench-lib-' || g, 'bench-lib-' || g
            FROM generate_series(1, 5) o, generate_series(1, 50) g;

            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, origin)
            SELECT 'bench-pv-' || p.id, p.id, '1.0.0', 'pkg:npm/' || p.name || '@1.0.0-' || p.id, 'hosted/' || p.id, 1, 'c', 'uploaded'
            FROM packages p WHERE p.id LIKE 'bench-pkg-%';
            """,
            new { defaultOrg });
    }

    private static async Task PrimeProxiedPackageAsync(DependablyFactory factory, string token)
    {
        factory.MockUpstream.Given(
                Request.Create().UsingGet().WithPath($"/flatcontainer/{NuGetId}/1.0.0/{NuGetId}.1.0.0.nupkg"))
            .RespondWith(Response.Create().WithStatusCode(HttpStatusCode.OK)
                .WithHeader("Content-Type", "application/octet-stream")
                .WithBody(new byte[4096]));

        using var client = factory.CreateClientWithBearer(token);
        var resp = await client.GetAsync($"/nuget/flatcontainer/{NuGetId}/1.0.0/{NuGetId}.1.0.0.nupkg");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    private static async Task PublishHostedPackageAsync(DependablyFactory factory, string token)
    {
        using var client = factory.CreateClientWithBearer(token);
        using var content = new StringContent(NpmFixtures.BuildPublishBody(NpmName, "1.0.0"), Encoding.UTF8, "application/json");
        var resp = await client.PutAsync($"/npm/{NpmName}", content);
        Assert.True(resp.IsSuccessStatusCode, $"publish returned {(int)resp.StatusCode}");
    }

    // The candidate policy for the version-scoped tables: a version row is visible when its parent
    // package is. packages is itself under RLS, so the EXISTS already sees only the tenant's rows;
    // the org_id comparison keeps the predicate correct even for a role that bypassed packages' policy.
    private static async Task AddVersionPolicyAsync(DependablyFactory factory)
    {
        await using var conn = await factory.Services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("benchmark: trial version policy");
        await conn.ExecuteAsync(
            """
            ALTER TABLE package_versions ENABLE ROW LEVEL SECURITY;
            CREATE POLICY bench_version_isolation ON package_versions
                USING (EXISTS (SELECT 1 FROM packages p
                               WHERE p.id = package_versions.package_id
                                 AND p.org_id = (SELECT dependably_current_org())));
            """);
    }

    private static async Task AnalyzeAsync(DependablyFactory factory)
    {
        await using var conn = await factory.Services.GetRequiredService<IMetadataStore>()
            .OpenCrossTenantAsync("benchmark: planner statistics");
        await conn.ExecuteAsync("ANALYZE packages, package_versions, cache_artifact, tenant_artifact_access, orgs");
    }
}
