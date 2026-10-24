using System.Text;
using System.Text.RegularExpressions;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Cost of the vulnerability report page, its count and the SIEM summary at about 100,000
/// <c>package_version_vulns</c> rows, on a file-backed SQLite database built from the real schema
/// and on live Postgres. Each case prints its wall time and its query plan to the test output so a
/// change to the report SQL can be compared before and after; the only hard assertion is a generous
/// ceiling that catches an accidental return to per-row donor evaluation, not a tuned budget.
///
/// <para>Dataset: 1,000 GHSA advisories carrying severity, score and summary, each with a PYSEC
/// twin that carries none of them and names the GHSA as an alias. Every version links two GHSA/PYSEC
/// pairs (four links), so half the rows need both donors. Org 0 owns 16,000 uploaded versions
/// (64,000 links) and reaches 5,000 proxied artefacts (20,000 links); four more orgs own 1,000
/// versions each (16,000 links); org 1 reaches the same proxied artefacts.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class VulnReportScaleTests(ITestOutputHelper output)
{
    private const int Pairs = 1000;
    private const int BigOrgVersions = 16000;
    private const int SmallOrgVersions = 1000;
    private const int SmallOrgs = 4;
    private const int CacheArtifacts = 5000;
    private const double CeilingSeconds = 30;

    [Fact]
    public async Task Sqlite_FileBacked_ReportCostAtScale()
    {
        string? keep = Environment.GetEnvironmentVariable("VULN_SCALE_SQLITE_PATH");
        string path = keep ?? Path.Combine(Path.GetTempPath(), $"vuln-scale-{Guid.NewGuid():N}.db");
        try
        {
            var store = new SqliteMetadataStore($"Data Source={path}");
            await new SchemaInitializer(store).InitializeAsync();
            await RunAsync("sqlite", store);
        }
        finally
        {
            if (keep is null)
            {
                foreach (string f in new[] { path, path + "-wal", path + "-shm" })
                {
                    File.Delete(f);
                }
            }
        }
    }

    internal async Task RunAsync(string engine, IMetadataStore store)
    {
        var clock = TimeProvider.System;
        long t0 = clock.GetTimestamp();
        string[] orgs = await SeedAsync(store);
        string org0 = orgs[0];
        long sweepStart = clock.GetTimestamp();
        await using (var conn = await store.OpenAsync())
        {
            int resolved = await VulnerabilityRepository.ResolveStaleAliasDonorsAsync(conn, clock);
            output.WriteLine($"[{engine}] boot sweep resolved {resolved} links in {clock.GetElapsedTime(sweepStart).TotalSeconds:F1}s");
        }

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(new CommandDefinition("ANALYZE", commandType: System.Data.CommandType.Text, commandTimeout: 300));
        }

        long links;
        await using (var conn = await store.OpenAsync())
        {
            links = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_version_vulns");
        }

        output.WriteLine($"[{engine}] seeded {links} package_version_vulns rows in {clock.GetElapsedTime(t0).TotalSeconds:F1}s");
        Assert.InRange(links, 95_000, 105_000);
        if (Environment.GetEnvironmentVariable("VULN_SCALE_SEED_ONLY") == "1")
        {
            string dump = Environment.GetEnvironmentVariable("VULN_SCALE_PLAN_DIR") ?? Path.GetTempPath();
            await File.WriteAllTextAsync(Path.Combine(dump, "report_rows.sql"), VulnerabilityRepository.ReportRowsSql);
            await File.WriteAllTextAsync(Path.Combine(dump, "summary.sql"), VulnerabilityRepository.SeveritySummarySql);
            await File.WriteAllTextAsync(Path.Combine(dump, "org0.txt"), org0);
            return;
        }

        var repo = new VulnerabilityRepository(store, clock);
        object noSearch = new { orgId = org0, ecosystem = (string?)null, purlName = (string?)null, searchPattern = (string?)null, limit = 50, offset = 0 };
        object search = new { orgId = org0, ecosystem = (string?)null, purlName = (string?)null, searchPattern = "%remote code%", limit = 50, offset = 0 };
        object siem = new { orgId = (string?)null };
        object orgOnly = new { orgId = org0 };

        string wrapped = "SELECT COUNT(*) FROM (" + VulnerabilityRepository.ReportRowsSql + ") u";
        string riskPage = "SELECT * FROM (" + VulnerabilityRepository.ReportRowsSql + ") u "
            + "ORDER BY IsKev DESC, COALESCE(EpssScore, -1) DESC, COALESCE(CvssScore, -1) DESC, Purl, OsvId LIMIT @limit OFFSET @offset";
        string severityPage = "SELECT * FROM (" + VulnerabilityRepository.ReportRowsSql + ") u "
            + "ORDER BY CASE LOWER(Severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, Purl, OsvId LIMIT @limit OFFSET @offset";

        var cases = new (string Name, string Sql, object Args)[]
        {
            ("count, wrapped ReportRowsSql, no search", wrapped, noSearch),
            ("count, count-specific SQL, no search", VulnerabilityRepository.CountRowsSql, noSearch),
            ("count, wrapped ReportRowsSql, search", wrapped, search),
            ("count, count-specific SQL, search", VulnerabilityRepository.CountRowsSearchSql, search),
            ("page, risk sort, no search", riskPage, noSearch),
            ("page, severity sort, no search", severityPage, noSearch),
            ("page, risk sort, search", riskPage, search),
            ("SIEM severity summary (instance-wide)", VulnerabilityRepository.SeveritySummarySql, siem),
            ("severity summary (one org)", VulnerabilityRepository.SeveritySummarySql, orgOnly),
        };

        var plans = new StringBuilder();
        double slowest = 0;
        foreach (var (name, sql, args) in cases)
        {
            var (seconds, cpu) = await TimeAsync(store, sql, args);
            output.WriteLine($"[{engine}] {name}: {seconds * 1000:F0} ms wall, {cpu * 1000:F0} ms process cpu");
            plans.AppendLine($"--- [{engine}] {name}").AppendLine(await ExplainAsync(store, sql, args));
            if (!name.Contains("wrapped", StringComparison.Ordinal))
            {
                slowest = Math.Max(slowest, seconds);
            }
        }

        long t = clock.GetTimestamp();
        var (items, total) = await repo.GetVulnReportAsync(new VulnReportQuery(org0));
        output.WriteLine($"[{engine}] GetVulnReportAsync end to end (count + page + finish): {clock.GetElapsedTime(t).TotalMilliseconds:F0} ms, total={total}, items={items.Count}");
        t = clock.GetTimestamp();
        await repo.GetVulnSummaryAsync(null, CancellationToken.None);
        output.WriteLine($"[{engine}] GetVulnSummaryAsync(instance-wide) end to end: {clock.GetElapsedTime(t).TotalMilliseconds:F0} ms");

        await SteadyStateAsync(engine, store, repo, org0);

        string? planDir = Environment.GetEnvironmentVariable("VULN_SCALE_PLAN_DIR");
        if (!string.IsNullOrEmpty(planDir))
        {
            Directory.CreateDirectory(planDir);
            await File.WriteAllTextAsync(Path.Combine(planDir, $"{engine}.plans.txt"), plans.ToString());
        }

        Assert.True(slowest < CeilingSeconds, $"the slowest report query took {slowest:F1}s on {engine}");
    }

    // After the boot sweep every link is current: a further sweep matches nothing, and so does one
    // after every advisory has been re-fetched unchanged (the daily rescan). On SQLite a full
    // re-resolve of every link, run while another connection writes, must not fail that writer.
    private async Task SteadyStateAsync(string engine, IMetadataStore store, VulnerabilityRepository repo, string org0)
    {
        var clock = TimeProvider.System;
        long t = clock.GetTimestamp();
        int idle = await repo.ReconcileAliasDonorsAsync();
        output.WriteLine($"[{engine}] steady-state sweep, nothing changed: {idle} links, {clock.GetElapsedTime(t).TotalMilliseconds:F0} ms");
        Assert.Equal(0, idle);

        t = clock.GetTimestamp();
        for (int i = 0; i < Pairs; i++)
        {
            string severity = (i % 4) switch { 0 => "CRITICAL", 1 => "HIGH", 2 => "MEDIUM", _ => "LOW" };
            await repo.UpsertVulnerabilityAsync(
                new Dependably.Protocol.OsvAdvisory($"GHSA-{i}", [], $"Advisory {i} allows remote code execution", severity,
                    1.0 + (i % 90) / 10.0, [], null, null, IsHydrated: true), "PyPI", "pkg");
            await repo.UpsertVulnerabilityAsync(
                new Dependably.Protocol.OsvAdvisory($"PYSEC-{i}", [$"GHSA-{i}"], null, null, null, [], null, null, IsHydrated: true),
                "PyPI", "pkg");
        }

        output.WriteLine($"[{engine}] re-fetched {Pairs * 2} advisories unchanged in {clock.GetElapsedTime(t).TotalSeconds:F1}s");
        t = clock.GetTimestamp();
        int afterRefetch = await repo.ReconcileAliasDonorsAsync();
        output.WriteLine($"[{engine}] steady-state sweep after an unchanged re-fetch of every advisory: {afterRefetch} links, {clock.GetElapsedTime(t).TotalMilliseconds:F0} ms");
        Assert.Equal(0, afterRefetch);

        if (store.Provider != DbProvider.Sqlite)
        {
            return;
        }

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE package_version_vulns SET alias_resolved_at = NULL");
        }

        t = clock.GetTimestamp();
        var run = await RunCountedSweepAsync((SqliteMetadataStore)store, org0);
        double sweepSeconds = clock.GetElapsedTime(t).TotalSeconds;
        output.WriteLine($"[{engine}] full re-resolve of {run.Result} links in {sweepSeconds:F1}s: {run.Describe()}");
        Assert.True(run.Result >= 100_000);
        run.AssertWritersUnharmed();

        // The sweep resolves owners in many short statements, none touching more owners than a
        // batch, and yields between them: not one statement over every link.
        var resolveUpdates = run.Writes("UPDATE package_version_vulns");
        Assert.All(resolveUpdates, u => Assert.InRange(PlaceholdersIn(u), 1, VulnerabilityRepository.SweepBatchOwners));
        Assert.True(resolveUpdates.Count >= 20_000 / VulnerabilityRepository.SweepBatchOwners,
            $"{resolveUpdates.Count} resolve statements");
        Assert.True(run.Pauses >= resolveUpdates.Count - 2, $"{run.Pauses} pauses for {resolveUpdates.Count} statements");
    }

    // Matches the bound id placeholders (@o0, @o1, ... for owners; @v0, ... for advisories) of one
    // batched statement.
    private static int PlaceholdersIn(string statement) =>
        Regex.Count(statement, @"@[ov]\d+", RegexOptions.None, TimeSpan.FromSeconds(5));

    private static readonly string[] WriteVerbs = ["UPDATE", "INSERT", "DELETE"];

    private sealed record CountedSweep(
        int Result, IReadOnlyList<string> Statements, int Pauses, int WriterWrites, double SlowestWrite,
        IReadOnlyList<Exception> Failures)
    {
        public IReadOnlyList<string> Writes(string prefix) =>
            Statements.Where(s => s.StartsWith(prefix, StringComparison.Ordinal)).ToList();

        public IReadOnlyList<string> AllWrites =>
            Statements.Where(s => WriteVerbs.Any(v => s.StartsWith(v, StringComparison.Ordinal))).ToList();

        public string Describe() =>
            $"{AllWrites.Count} write statements, {Pauses} pauses; {WriterWrites} concurrent writes, "
            + $"{Failures.Count} failed, slowest {SlowestWrite * 1000:F0} ms";

        // What must hold on any host: every concurrent write succeeded. A write blocked by the
        // sweep's write lock keeps retrying until the command timeout and fails only then, so a
        // write that waited long still succeeds and a slow runner stretches the wait without
        // breaking anything; the wait is therefore reported, not bounded. That the sweep holds the
        // lock only briefly is asserted from its statements (bounded batches, pauses, no write on
        // a no-op sweep), which does not depend on the host's speed.
        public void AssertWritersUnharmed()
        {
            Assert.Empty(Failures);
            Assert.True(WriterWrites > 0, "no concurrent write ran during the sweep");
        }
    }

    // Runs the alias-donor sweep through a statement-counting store while another connection keeps
    // writing, and reports the statements the sweep issued, its pauses, and what the writer saw.
    private static async Task<CountedSweep> RunCountedSweepAsync(SqliteMetadataStore store, string org)
    {
        await using var counting = new CountingStore(store);
        var clock = new PauseCountingTimeProvider();
        var repo = new VulnerabilityRepository(counting, clock);
        var failures = new List<Exception>();
        double worst = 0;
        int writes = 0;
        var running = Task.Run(() => repo.ReconcileAliasDonorsAsync());
        while (!running.IsCompleted)
        {
            long w = TimeProvider.System.GetTimestamp();
            try
            {
                await using var writer = await store.OpenAsync();
                await writer.ExecuteAsync("UPDATE orgs SET slug = slug WHERE id = @org", new { org });
                writes++;
            }
            catch (Exception ex)
            {
                failures.Add(ex);
            }

            worst = Math.Max(worst, TimeProvider.System.GetElapsedTime(w).TotalSeconds);
            await Task.Delay(TimeSpan.FromMilliseconds(5));
        }

        int result = await running;
        var conn = Assert.Single(counting.Connections);
        return new CountedSweep(result, conn.Statements.Select(x => x.TrimStart()).ToList(), clock.Pauses, writes, worst, failures);
    }

    // A large advisory table whose rows carry the full advisory document (the donor columns sit
    // behind it): the first fill of every advisory's basis is written in bounded batches, and a
    // steady-state sweep that finds nothing writes nothing, so neither can hold the write lock
    // long enough to fail a concurrent SQLite writer.
    [Fact]
    public async Task Sqlite_AdvisoryBasisSweep_DoesNotHoldTheWriteLock()
    {
        string path = Path.Combine(Path.GetTempPath(), $"vuln-basis-{Guid.NewGuid():N}.db");
        try
        {
            var store = new SqliteMetadataStore($"Data Source={path}");
            await new SchemaInitializer(store).InitializeAsync();
            string org = await OrgSeeder.InsertAsync(store, $"basis-{Guid.NewGuid():N}"[..20]);
            await using (var conn = await store.OpenAsync())
            {
                await conn.ExecuteAsync(
                    """
                    WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 50000)
                    INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, osv_json)
                    SELECT 'adv-' || i, 'GHSA-big-' || i, 'PyPI', 'pkg', 'HIGH', 7.5, 'summary ' || i, hex(zeroblob(4000)) FROM n
                    """);
            }

            var clock = TimeProvider.System;
            foreach (string phase in new[] { "first fill", "no-op" })
            {
                long t = clock.GetTimestamp();
                var run = await RunCountedSweepAsync(store, org);
                output.WriteLine($"[sqlite] advisory basis sweep, {phase}, 50000 advisories x 8 KB: "
                    + $"{clock.GetElapsedTime(t).TotalSeconds:F1}s; {run.Describe()}");
                run.AssertWritersUnharmed();

                if (phase == "no-op")
                {
                    // Nothing changed: the sweep only reads, so it never takes the write lock.
                    Assert.Empty(run.AllWrites);
                    continue;
                }

                // The first fill writes every advisory's basis in short batches, with pauses
                // between them, not in one statement over the table.
                var fills = run.Writes("UPDATE vulnerabilities");
                Assert.All(fills, u => Assert.InRange(PlaceholdersIn(u), 1, VulnerabilityRepository.SweepBatchOwners));
                Assert.Equal(50_000, fills.Sum(PlaceholdersIn));
                Assert.True(fills.Count >= 50_000 / VulnerabilityRepository.SweepBatchOwners, $"{fills.Count} fill statements");
                Assert.True(run.Pauses >= fills.Count - 1, $"{run.Pauses} pauses for {fills.Count} batches");
            }
        }
        finally
        {
            foreach (string f in new[] { path, path + "-wal", path + "-shm", path + "-journal" })
            {
                File.Delete(f);
            }
        }
    }

    private static async Task<(double Wall, double Cpu)> TimeAsync(IMetadataStore store, string sql, object args)
    {
        var clock = TimeProvider.System;
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        var samples = new List<(double Wall, double Cpu)>();
        for (int i = 0; i < 3; i++)
        {
            await using var conn = await store.OpenAsync();
            process.Refresh();
            var cpuBefore = process.TotalProcessorTime;
            long t = clock.GetTimestamp();
            await conn.QueryAsync<dynamic>(new CommandDefinition(sql, args, commandTimeout: 300));
            double wall = clock.GetElapsedTime(t).TotalSeconds;
            process.Refresh();
            samples.Add((wall, (process.TotalProcessorTime - cpuBefore).TotalSeconds));
        }

        // The first run warms the page cache and the plan cache. The fastest of the rest is the
        // figure for each measure, the least disturbed by whatever else the machine is running; the
        // CPU time is the in-process work, which is the SQLite engine's own cost and only the
        // client's share against Postgres.
        samples.RemoveAt(0);
        return (samples.Min(x => x.Wall), samples.Min(x => x.Cpu));
    }

    private static async Task<string> ExplainAsync(IMetadataStore store, string sql, object args)
    {
        await using var conn = await store.OpenAsync();
        string prefix = store.Provider == DbProvider.Sqlite ? "EXPLAIN QUERY PLAN " : "EXPLAIN (ANALYZE, BUFFERS) ";
        var sb = new StringBuilder();
        var rows = await conn.QueryAsync<dynamic>(new CommandDefinition(prefix + sql, args, commandTimeout: 300));
        foreach (IDictionary<string, object> row in rows)
        {
            sb.AppendLine(string.Join(" | ", row.Values.Skip(store.Provider == DbProvider.Sqlite ? 3 : 0)));
        }

        return sb.ToString();
    }

    private static async Task<string[]> SeedAsync(IMetadataStore store)
    {
        var orgs = new List<string>();
        for (int i = 0; i <= SmallOrgs; i++)
        {
            orgs.Add(await OrgSeeder.InsertAsync(store, $"scale-{i}-{Guid.NewGuid():N}"[..20]));
        }

        await using var conn = await store.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();

        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < @pairs - 1)
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, aliases)
            SELECT 'g' || i, 'GHSA-' || i, 'PyPI', 'pkg', 
                   CASE i % 4 WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'LOW' END,
                   1.0 + (i % 90) / 10.0, 'Advisory ' || i || ' allows remote code execution', NULL
            FROM n
            """,
            new { pairs = Pairs }, tx);
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < @pairs - 1)
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, summary, aliases)
            SELECT 'p' || i, 'PYSEC-' || i, 'PyPI', 'pkg', NULL, NULL, NULL, '["GHSA-' || i || '"]'
            FROM n
            """,
            new { pairs = Pairs }, tx);

        for (int o = 0; o < orgs.Count; o++)
        {
            int versions = o == 0 ? BigOrgVersions : SmallOrgVersions;
            var p = new { org = orgs[o], tag = $"o{o}", versions, pairs = Pairs };
            await conn.ExecuteAsync(
                """
                WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < (@versions + 9) / 10)
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
                SELECT @tag || '-pkg-' || i, @org, 'pypi', 'pkg-' || @tag || '-' || i, 'pkg-' || @tag || '-' || i, 0 FROM n
                """, p, tx);
            await conn.ExecuteAsync(
                """
                WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @versions)
                INSERT INTO package_versions (id, package_id, version, purl, blob_key, filename, size_bytes, origin)
                SELECT @tag || '-pv-' || i, @tag || '-pkg-' || ((i + 9) / 10), '1.' || i,
                       'pkg:pypi/pkg-' || @tag || '-' || ((i + 9) / 10) || '@1.' || i,
                       'blob/' || @tag || '/' || i, 'f-' || @tag || '-' || i || '.whl', 100, 'uploaded'
                FROM n
                """, p, tx);
            foreach (string vulnKind in new[] { "g", "p" })
            {
                foreach (string slot in new[] { "a", "b" })
                {
                    // Slot a is pair (i % pairs); slot b is a different pair, never equal to a.
                    string pairExpr = slot == "a" ? "(i % @pairs)" : "((i % @pairs + 1 + (i % 997)) % @pairs)";
                    // rawsql: pairExpr is one of two literals above; every value is a bound parameter.
                    await conn.ExecuteAsync(
                        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @versions) "
                        + "INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind) "
                        + $"SELECT @tag || '-l-{vulnKind}{slot}-' || i, @tag || '-pv-' || i, '{vulnKind}' || {pairExpr}, 'package_version' FROM n",
                        p, tx);
                }
            }
        }

        var c = new { org0 = orgs[0], org1 = orgs[1], n = CacheArtifacts, pairs = Pairs };
        await conn.ExecuteAsync(
            """
            WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @n)
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            SELECT 'ca-' || i, 'pypi', 'cached-' || ((i + 4) / 5), '2.' || i, 'c-' || i || '.whl', 'proxy/' || i, 'h' || i, 0,
                   'pkg:pypi/cached-' || ((i + 4) / 5) || '@2.' || i
            FROM n
            """, c, tx);
        foreach (string org in new[] { "org0", "org1" })
        {
            await conn.ExecuteAsync(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @n) "
                + "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) "
                + $"SELECT @{org}, 'ca-' || i FROM n",
                c, tx);
        }

        foreach (string vulnKind in new[] { "g", "p" })
        {
            foreach (string slot in new[] { "a", "b" })
            {
                string pairExpr = slot == "a" ? "(i % @pairs)" : "((i % @pairs + 1 + (i % 997)) % @pairs)";
                await conn.ExecuteAsync(
                    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < @n) "
                    + "INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind) "
                    + $"SELECT 'cl-{vulnKind}{slot}-' || i, 'ca-' || i, '{vulnKind}' || {pairExpr}, 'cache_artifact' FROM n",
                    c, tx);
            }
        }

        await tx.CommitAsync();
        return orgs.ToArray();
    }
}
