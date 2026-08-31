using System.Data.Common;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>A resolved (project, version) pair, as an ingest read needs it before it parses.</summary>
public sealed record ProjectVersionRef(
    string ProjectId, string ProjectName, string ProjectKind, string ProjectVersionId, string VersionLabel);

/// <summary>
/// One component as an SBOM declares it. Carries only SBOM-owned facts: the dev/prod signal
/// lives in <c>dependency_scope</c>, which the reachability scanner owns and this record has no
/// field for, so the merge cannot write it even by accident.
/// </summary>
public sealed record SbomComponentUpsert(
    string? Purl,
    string? Ecosystem,
    string? PurlName,
    string? Version,
    string Name,
    string? ComponentType,
    string? SbomScope,
    string? DependencyKind,
    string? DependencyPath,
    string? LicenseSpdx,
    string? Description = null,
    string? ComponentAuthor = null,
    string? Copyright = null,
    string? ComponentGroup = null,
    string? WebsiteUrl = null,
    string? VcsUrl = null,
    string? IssueTrackerUrl = null,
    string? DistributionUrl = null,
    string? ComponentHashes = null);

/// <summary>What one merge did, for the upload response.</summary>
public sealed record SbomComponentMergeCounts(int Total, int Added, int Removed, int Unchanged);

/// <summary>One component row as it currently stands, for matching and for the merge diff.</summary>
public sealed class SbomComponentRow
{
    public string Id { get; set; } = "";
    public string? Purl { get; set; }
    public string? Ecosystem { get; set; }
    public string? PurlName { get; set; }
    public string? Version { get; set; }
    public string Name { get; set; } = "";
    public string? ComponentType { get; set; }
    public string? SbomScope { get; set; }
    public string? DependencyKind { get; set; }
    public string? DependencyPath { get; set; }
    public string? LicenseSpdx { get; set; }
    public string? Description { get; set; }
    public string? ComponentAuthor { get; set; }
    public string? Copyright { get; set; }
    public string? ComponentGroup { get; set; }
    public string? WebsiteUrl { get; set; }
    public string? VcsUrl { get; set; }
    public string? IssueTrackerUrl { get; set; }
    public string? DistributionUrl { get; set; }
    public string? ComponentHashes { get; set; }
}

/// <summary>The VEX arm of one analysis row, as a document asserts it.</summary>
public sealed record VexStatementWrite(
    string PurlKey, string VulnKey, string? State, string? Justification, string? Response, string? Detail);

/// <summary>The reachability arm of one analysis row, as a SARIF log asserts it.</summary>
public sealed record SarifFactWrite(
    string PurlKey,
    string VulnKey,
    string? Reachability,
    string? Confidence,
    bool Suppressed,
    double? SecuritySeverity,
    string? SeverityOrigin,
    string? Fingerprint);

/// <summary>The natural key of one <c>project_vuln_analysis</c> row.</summary>
public readonly record struct AnalysisRowKey(string PurlKey, string VulnKey);

/// <summary>The component-level facts only a codebase scan can supply.</summary>
public sealed record SbomComponentFactWrite(
    string ComponentId, string DependencyScope, string? DependencyKind, string? DependencyPath);

/// <summary>
/// The write side of document ingest: the component merge and the two arms of
/// <c>project_vuln_analysis</c>.
///
/// <para>Ingest is a re-runnable pure merge — components from the latest SBOM, then the latest
/// VEX, then the latest SARIF — so every write here is an upsert keyed on something stable
/// rather than an append. That is what lets a re-uploaded SBOM re-run the version's already-stored
/// VEX and SARIF against the inventory it just wrote. A VEX or a SARIF still needs its version's
/// SBOM already in place: the version itself only exists once an SBOM has created it, so the
/// upload order across document kinds is fixed — SBOM first, then VEX and SARIF in either
/// order.</para>
///
/// <para>The two analysis arms are written by separate statements that name only their own
/// columns. A single upsert covering both would make each document kind silently erase the
/// other's facts on every re-upload, which is the failure the split-arm row exists to prevent.</para>
///
/// <para><b>An upsert alone is not latest-wins.</b> Latest-wins means the stored state is exactly
/// what the current documents assert — so a statement a new document drops has to be retracted,
/// not merely left unrefreshed. Retraction by omission is how VEX withdraws an assertion: the
/// producer republishes the document without the statement. Leaving the old row in place keeps a
/// withdrawn <c>not_affected</c> suppressing a finding forever, which is the fail-open direction
/// on a security gate, so <see cref="RetractUnassertedVexAsync"/> and
/// <see cref="RetractUnassertedSarifAsync"/> clear the arms of the rows the current documents no
/// longer name. Manually triaged rows are exempt — an operator's decision is not something an
/// uploaded document may withdraw, the same rule <see cref="UpsertVexBatchAsync"/> enforces on the
/// write side.</para>
/// </summary>
public sealed class SbomIngestRepository
{
    private readonly IMetadataStore _db;

    public SbomIngestRepository(IMetadataStore db)
    {
        _db = db;
    }

    /// <summary>
    /// Resolves an existing (project, version) pair by name without creating anything — the
    /// read the dedup check needs before a document has been parsed. Returns null when either
    /// half is unknown.
    /// </summary>
    /// <summary>
    /// Every (project, version) pair matching this name — plural on purpose. A project name is
    /// unique per PARENT SCOPE, not per org, so once collections exist two folders may each hold a
    /// <c>api</c>, and a single-row read of this query throws rather than answering. Callers pass
    /// <paramref name="parentId"/> to name one scope, and report the ambiguity when they cannot.
    ///
    /// A null <paramref name="parentId"/> deliberately does NOT mean "the root scope": it means
    /// the caller did not say, which is the Dependency-Track-compatible CI shape. Narrowing it to
    /// the root would silently stop resolving every project anyone had filed into a folder.
    /// </summary>
    public async Task<IReadOnlyList<ProjectVersionRef>> ResolveVersionCandidatesAsync(
        string orgId, string projectName, string projectVersion, string? parentId = null,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<ProjectVersionRef>(new CommandDefinition(
            """
            SELECT p.id AS ProjectId, p.name AS ProjectName, p.kind AS ProjectKind,
                   v.id AS ProjectVersionId, v.version AS VersionLabel
            FROM project_versions v
            JOIN projects p ON p.id = v.project_id AND p.org_id = v.org_id
            WHERE v.org_id = @orgId AND p.name = @projectName AND v.version = @projectVersion
              AND (@parentId IS NULL OR p.parent_id = @parentId)
            ORDER BY p.id
            """,
            new { orgId, projectName, projectVersion, parentId },
            cancellationToken: ct));
        return rows.AsList();
    }

    /// <summary>Every component row held for one version.</summary>
    public async Task<IReadOnlyList<SbomComponentRow>> ListComponentsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<SbomComponentRow>(new CommandDefinition(
            ComponentSelectSql,
            new { orgId, projectVersionId },
            cancellationToken: ct));
        return rows.ToList();
    }

    /// <summary>How many components one version currently holds.</summary>
    public async Task<int> CountComponentsAsync(
        string orgId, string projectVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            """
            SELECT COUNT(*) FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
            """,
            new { orgId, projectVersionId },
            cancellationToken: ct));
    }

    private const string ComponentSelectSql = """
        SELECT id AS Id, purl AS Purl, ecosystem AS Ecosystem, purl_name AS PurlName,
               version AS Version, name AS Name, component_type AS ComponentType,
               sbom_scope AS SbomScope, dependency_kind AS DependencyKind,
               dependency_path AS DependencyPath, license_spdx AS LicenseSpdx,
               description AS Description, component_author AS ComponentAuthor,
               copyright AS Copyright, component_group AS ComponentGroup,
               website_url AS WebsiteUrl, vcs_url AS VcsUrl,
               issue_tracker_url AS IssueTrackerUrl, distribution_url AS DistributionUrl,
               component_hashes AS ComponentHashes
        FROM sbom_components
        WHERE org_id = @orgId AND project_version_id = @projectVersionId
        """;

    /// <summary>
    /// Replaces one version's inventory with <paramref name="components"/>, matching existing
    /// rows on the verbatim purl (and on name@version for the purl-less rows the unique index
    /// cannot cover). Matched rows are updated in place so their id survives, which is what
    /// keeps advisory links and per-component reachability facts attached across a re-upload of
    /// an SBOM whose inventory did not change.
    /// </summary>
    public async Task<SbomComponentMergeCounts> MergeComponentsAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyList<SbomComponentUpsert> components,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            var existing = (await conn.QueryAsync<SbomComponentRow>(new CommandDefinition(
                ComponentSelectSql, new { orgId, projectVersionId }, dbTx, cancellationToken: ct)))
                .ToList();

            var byKey = new Dictionary<string, SbomComponentRow>(StringComparer.Ordinal);
            foreach (var row in existing)
            {
                byKey[MergeKey(row.Purl, row.Name, row.Version)] = row;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            int added = 0;
            int unchanged = 0;

            foreach (var component in components)
            {
                string key = MergeKey(component.Purl, component.Name, component.Version);
                if (!seen.Add(key))
                {
                    // Two entries collapsing to one key describe the same component twice; the
                    // first wins so the count matches the rows that exist.
                    continue;
                }

                if (!byKey.TryGetValue(key, out var row))
                {
                    await InsertComponentAsync(conn, dbTx, orgId, projectVersionId, component, now, ct);
                    added++;
                    continue;
                }

                if (IsUnchanged(row, component))
                {
                    unchanged++;
                    continue;
                }

                await UpdateComponentAsync(conn, dbTx, orgId, row.Id, component, ct);
            }

            int removed = 0;
            foreach (var (key, row) in byKey)
            {
                if (seen.Contains(key))
                {
                    continue;
                }

                await conn.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM sbom_components WHERE id = @id AND org_id = @orgId",
                    new { id = row.Id, orgId }, dbTx, cancellationToken: ct));
                removed++;
            }

            await dbTx.CommitAsync(ct);
            return new SbomComponentMergeCounts(seen.Count, added, removed, unchanged);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    // The purl is the identity when the component declares one; name@version is the only key a
    // purl-less component has. The two key spaces are kept apart by the prefix so a component
    // named "pkg:npm/x" cannot collide with a purl. The separator is "|" -- printable and absent
    // from an unescaped purl, unlike a raw NUL byte, which reads back fine at runtime but makes
    // this file register as binary to grep/ripgrep, a reviewability cost this key never needed
    // to pay for a key that lives and dies inside one merge call.
    private static string MergeKey(string? purl, string name, string? version) =>
        purl is not null
            ? "purl|" + purl
            : "name|" + name + "|" + (version ?? string.Empty);

    private static bool IsUnchanged(SbomComponentRow row, SbomComponentUpsert component) =>
        row.Ecosystem == component.Ecosystem
        && row.PurlName == component.PurlName
        && row.Version == component.Version
        && row.Name == component.Name
        && row.ComponentType == component.ComponentType
        && row.SbomScope == component.SbomScope
        && row.DependencyKind == component.DependencyKind
        && row.DependencyPath == component.DependencyPath
        && row.LicenseSpdx == component.LicenseSpdx
        // Every column the update writes has to be compared here. A field compared nowhere is a
        // field that never updates on a row that already exists: the merge would report the
        // component unchanged and skip the write, so widening the projection would appear to do
        // nothing for every component whose identity happens to be stable.
        && row.Description == component.Description
        && row.ComponentAuthor == component.ComponentAuthor
        && row.Copyright == component.Copyright
        && row.ComponentGroup == component.ComponentGroup
        && row.WebsiteUrl == component.WebsiteUrl
        && row.VcsUrl == component.VcsUrl
        && row.IssueTrackerUrl == component.IssueTrackerUrl
        && row.DistributionUrl == component.DistributionUrl
        && row.ComponentHashes == component.ComponentHashes;

    // dependency_scope is absent from both statements on purpose: it is the reachability
    // scanner's column, and an insert that named it would reset a scanned component to
    // 'unknown' every time its SBOM was re-uploaded.
    private static Task InsertComponentAsync(
        DbConnection conn,
        DbTransaction dbTx,
        string orgId,
        string projectVersionId,
        SbomComponentUpsert component,
        DateTimeOffset now,
        CancellationToken ct) =>
        conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO sbom_components (
                id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                component_type, sbom_scope, dependency_kind, dependency_path, license_spdx,
                description, component_author, copyright, component_group,
                website_url, vcs_url, issue_tracker_url, distribution_url, component_hashes,
                created_at)
            VALUES (
                @id, @orgId, @projectVersionId, @purl, @ecosystem, @purlName, @version, @name,
                @componentType, @sbomScope, @dependencyKind, @dependencyPath, @licenseSpdx,
                @description, @componentAuthor, @copyright, @componentGroup,
                @websiteUrl, @vcsUrl, @issueTrackerUrl, @distributionUrl, @componentHashes,
                @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                projectVersionId,
                purl = component.Purl,
                ecosystem = component.Ecosystem,
                purlName = component.PurlName,
                version = component.Version,
                name = component.Name,
                componentType = component.ComponentType,
                sbomScope = component.SbomScope,
                dependencyKind = component.DependencyKind,
                dependencyPath = component.DependencyPath,
                licenseSpdx = component.LicenseSpdx,
                description = component.Description,
                componentAuthor = component.ComponentAuthor,
                copyright = component.Copyright,
                componentGroup = component.ComponentGroup,
                websiteUrl = component.WebsiteUrl,
                vcsUrl = component.VcsUrl,
                issueTrackerUrl = component.IssueTrackerUrl,
                distributionUrl = component.DistributionUrl,
                componentHashes = component.ComponentHashes,
                now = now.ToUtcIso(),
            },
            dbTx,
            cancellationToken: ct));

    private static Task UpdateComponentAsync(
        DbConnection conn,
        DbTransaction dbTx,
        string orgId,
        string componentId,
        SbomComponentUpsert component,
        CancellationToken ct) =>
        conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE sbom_components SET
                ecosystem = @ecosystem,
                purl_name = @purlName,
                version = @version,
                name = @name,
                component_type = @componentType,
                sbom_scope = @sbomScope,
                dependency_kind = @dependencyKind,
                dependency_path = @dependencyPath,
                license_spdx = @licenseSpdx,
                description = @description,
                component_author = @componentAuthor,
                copyright = @copyright,
                component_group = @componentGroup,
                website_url = @websiteUrl,
                vcs_url = @vcsUrl,
                issue_tracker_url = @issueTrackerUrl,
                distribution_url = @distributionUrl,
                component_hashes = @componentHashes
            WHERE id = @componentId AND org_id = @orgId
            """,
            new
            {
                componentId,
                orgId,
                ecosystem = component.Ecosystem,
                purlName = component.PurlName,
                version = component.Version,
                name = component.Name,
                componentType = component.ComponentType,
                sbomScope = component.SbomScope,
                dependencyKind = component.DependencyKind,
                dependencyPath = component.DependencyPath,
                licenseSpdx = component.LicenseSpdx,
                description = component.Description,
                componentAuthor = component.ComponentAuthor,
                copyright = component.Copyright,
                componentGroup = component.ComponentGroup,
                websiteUrl = component.WebsiteUrl,
                vcsUrl = component.VcsUrl,
                issueTrackerUrl = component.IssueTrackerUrl,
                distributionUrl = component.DistributionUrl,
                componentHashes = component.ComponentHashes,
            },
            dbTx,
            cancellationToken: ct));

    /// <summary>
    /// Writes the VEX arm of one document's analysis rows, leaving the reachability arm
    /// untouched. A row is created when it does not exist, including for a statement naming a
    /// component this version's SBOM does not contain: an unmatched statement is a fact about
    /// the application the reader needs to see, not a parse error to discard.
    /// </summary>
    public async Task UpsertVexBatchAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyList<VexStatementWrite> writes,
        string? actorId,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        if (writes.Count == 0)
        {
            return;
        }

        // An operator's manual triage outranks an uploaded statement. The analysis merge is
        // re-runnable — every SBOM upload re-applies the stored VEX — so without this guard a
        // routine re-upload would silently revert a decision a human had already made, and the
        // suppression it carried would come back as an alert.
        //
        // The guard IS the conflict update's WHERE clause, so it only refuses a statement that
        // conflicts. The insert therefore resolves the spelling the stored row holds before it
        // writes vuln_key — the rule SbomVulnKeyComparer documents — because a document citing
        // CVE-X against a row triaged as cve-x would otherwise conflict with nothing, insert
        // alongside the manual row, and override the decision without ever meeting the guard.
        //
        // One connection and one transaction for the whole document, not one per write: a
        // document is allowed SbomDocumentLimits.MaxComponentStatements writes — the parser
        // charges its ceiling once per (statement, component) pair, which is exactly one row
        // here — and a connection opened per write turns one upload into that many sequential
        // round trips on the request thread. The transaction also makes the arm all-or-nothing,
        // so a failure part way through leaves no half-applied document behind.
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var write in writes)
            {
                await conn.ExecuteAsync(new CommandDefinition(
                    VexUpsertSql,
                    new
                    {
                        id = Guid.NewGuid().ToString("N"),
                        orgId,
                        projectVersionId,
                        purlKey = write.PurlKey,
                        vulnKey = write.VulnKey,
                        state = write.State,
                        justification = write.Justification,
                        response = write.Response,
                        detail = write.Detail,
                        actorId,
                        now = now.ToUtcIso(),
                    },
                    dbTx,
                    cancellationToken: ct));
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    private const string VexUpsertSql =
        """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                vex_state, vex_justification, vex_response, vex_detail, vex_source,
                updated_by, updated_at)
            SELECT @id, @orgId, @projectVersionId, @purlKey,
                   COALESCE((
                       SELECT stored.vuln_key
                       FROM project_vuln_analysis stored
                       WHERE stored.org_id = @orgId
                         AND stored.project_version_id = @projectVersionId
                         AND stored.purl_key = @purlKey
                         AND UPPER(stored.vuln_key) = UPPER(@vulnKey)
                       ORDER BY stored.vuln_key
                       LIMIT 1), @vulnKey),
                   @state, @justification, @response, @detail, 'upload', @actorId, @now
            WHERE true
            ON CONFLICT (project_version_id, purl_key, vuln_key) DO UPDATE SET
                vex_state = excluded.vex_state,
                vex_justification = excluded.vex_justification,
                vex_response = excluded.vex_response,
                vex_detail = excluded.vex_detail,
                vex_source = excluded.vex_source,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            WHERE COALESCE(project_vuln_analysis.vex_source, '') <> 'manual'
            """;

    /// <summary>
    /// Writes the reachability arm of one log's analysis rows, leaving the VEX arm untouched —
    /// so an uploaded SARIF never overwrites a triage decision, and a re-uploaded VEX never
    /// erases a reachability verdict.
    ///
    /// <para>The insert resolves the spelling the stored row holds before it writes
    /// <c>vuln_key</c>, the rule <see cref="SbomVulnKeyComparer"/> documents, so a log citing an
    /// advisory in a case the VEX did not use lands its reachability facts on that advisory's
    /// existing row rather than on a second one. The two arms name disjoint columns on both the
    /// insert and the conflict update, so landing on an existing row annotates it and changes
    /// nothing the VEX arm owns.</para>
    ///
    /// <para><c>updated_by</c>/<c>updated_at</c> are the exception, because they are row-level
    /// while the two arms have different authors. They name the VEX arm's author whenever a human
    /// decided it, and the last document to write the row otherwise: a manual triage is the only
    /// thing on the row a person is accountable for and the only thing the UI attributes by name —
    /// the triage editor renders "set by" from these two columns — while a reachability
    /// observation is signed by nobody. So this writer leaves both alone on a row whose VEX arm is
    /// manual, and writes every SARIF-owned column regardless, which is the point of landing on
    /// the row at all. <see cref="RetractUnassertedSarifAsync"/> skips its own
    /// <c>updated_at</c> write on the same rows for the same reason.</para>
    ///
    /// <para>The cost is explicit rather than hidden: on a manually triaged row the row-level
    /// timestamp stops tracking the reachability arm, so "when was this row's reachability last
    /// observed" is not answerable per row. It stays answerable per version, from the SARIF
    /// document receipt in <c>project_documents</c>, which records the log's own upload time.
    /// Answering it per row means a second column pair owned by the reachability arm — a schema
    /// change with a blue-green cost and, today, no reader. A wrong name against a decision is a
    /// worse answer than a missing timestamp against an observation.</para>
    /// </summary>
    public async Task UpsertSarifBatchAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyList<SarifFactWrite> writes,
        string? actorId,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        if (writes.Count == 0)
        {
            return;
        }

        // One connection and one transaction for the whole log, for the reason
        // UpsertVexBatchAsync states: a log is allowed SbomDocumentLimits.MaxResults results,
        // one row each, and a connection per result turns one upload into that many sequential
        // round trips.
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var write in writes)
            {
                await conn.ExecuteAsync(new CommandDefinition(
                    SarifUpsertSql,
                    new
                    {
                        id = Guid.NewGuid().ToString("N"),
                        orgId,
                        projectVersionId,
                        purlKey = write.PurlKey,
                        vulnKey = write.VulnKey,
                        reachability = write.Reachability,
                        confidence = write.Confidence,
                        suppressed = write.Suppressed ? 1 : 0,
                        securitySeverity = write.SecuritySeverity,
                        severityOrigin = write.SeverityOrigin,
                        fingerprint = write.Fingerprint,
                        actorId,
                        now = now.ToUtcIso(),
                    },
                    dbTx,
                    cancellationToken: ct));
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    private const string SarifUpsertSql =
        """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                reachability, confidence, sarif_suppressed, security_severity,
                severity_origin, fingerprint, updated_by, updated_at)
            SELECT @id, @orgId, @projectVersionId, @purlKey,
                   COALESCE((
                       SELECT stored.vuln_key
                       FROM project_vuln_analysis stored
                       WHERE stored.org_id = @orgId
                         AND stored.project_version_id = @projectVersionId
                         AND stored.purl_key = @purlKey
                         AND UPPER(stored.vuln_key) = UPPER(@vulnKey)
                       ORDER BY stored.vuln_key
                       LIMIT 1), @vulnKey),
                   @reachability, @confidence, @suppressed, @securitySeverity,
                   @severityOrigin, @fingerprint, @actorId, @now
            WHERE true
            ON CONFLICT (project_version_id, purl_key, vuln_key) DO UPDATE SET
                reachability = excluded.reachability,
                confidence = excluded.confidence,
                sarif_suppressed = excluded.sarif_suppressed,
                security_severity = excluded.security_severity,
                severity_origin = excluded.severity_origin,
                fingerprint = excluded.fingerprint,
                updated_by = CASE WHEN COALESCE(project_vuln_analysis.vex_source, '') = 'manual'
                                  THEN project_vuln_analysis.updated_by ELSE excluded.updated_by END,
                updated_at = CASE WHEN COALESCE(project_vuln_analysis.vex_source, '') = 'manual'
                                  THEN project_vuln_analysis.updated_at ELSE excluded.updated_at END
            """;

    /// <summary>
    /// Folds the component-level facts of a SARIF log onto their matched component rows. The
    /// dependency-kind and dependency-path columns are written only when the log carried them,
    /// so a producer that reports reachability but not graph position leaves the SBOM's own
    /// answer in place instead of blanking it.
    /// </summary>
    public async Task ApplyComponentFactsAsync(
        string orgId, IReadOnlyList<SbomComponentFactWrite> facts, CancellationToken ct = default)
    {
        if (facts.Count == 0)
        {
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        foreach (var fact in facts)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                """
                UPDATE sbom_components SET
                    dependency_scope = @dependencyScope,
                    dependency_kind = COALESCE(@dependencyKind, dependency_kind),
                    dependency_path = COALESCE(@dependencyPath, dependency_path)
                WHERE id = @componentId AND org_id = @orgId
                """,
                new
                {
                    componentId = fact.ComponentId,
                    orgId,
                    dependencyScope = fact.DependencyScope,
                    dependencyKind = fact.DependencyKind,
                    dependencyPath = fact.DependencyPath,
                },
                cancellationToken: ct));
        }
    }

    /// <summary>
    /// Clears the VEX arm of every upload-sourced row for this version that
    /// <paramref name="asserted"/> does not name, and deletes any row left carrying nothing at
    /// all. Manually triaged rows are never touched.
    ///
    /// <para>A stored row counts as named when <paramref name="asserted"/> holds its key under
    /// <see cref="SbomVulnKeyComparer"/> — the same rule the writer resolved its conflict key by.
    /// Matching ordinally instead would have this sweep fail to recognise a row the same request
    /// had just written, whenever the document's spelling differs from the stored one, and
    /// retract it on the spot.</para>
    /// </summary>
    /// <returns>How many rows had their VEX arm retracted.</returns>
    public async Task<int> RetractUnassertedVexAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyCollection<AnalysisRowKey> asserted,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var keep = BuildKeepSet(asserted);
        await using var conn = await _db.OpenAsync(ct);
        var candidates = (await conn.QueryAsync<AnalysisIdRow>(new CommandDefinition(
            """
            SELECT id AS Id, purl_key AS PurlKey, vuln_key AS VulnKey
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
              AND COALESCE(vex_source, '') = 'upload'
            """,
            new { orgId, projectVersionId },
            cancellationToken: ct))).ToList();

        int retracted = 0;
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var row in candidates)
            {
                if (keep.Contains((row.PurlKey, row.VulnKey)))
                {
                    continue;
                }

                await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE project_vuln_analysis SET
                        vex_state = NULL,
                        vex_justification = NULL,
                        vex_response = NULL,
                        vex_detail = NULL,
                        vex_source = NULL,
                        updated_at = @now
                    WHERE id = @id AND org_id = @orgId
                      AND COALESCE(vex_source, '') <> 'manual'
                    """,
                    new { id = row.Id, orgId, now = now.ToUtcIso() },
                    dbTx,
                    cancellationToken: ct));
                retracted++;
                await DeleteIfEmptyAsync(conn, dbTx, orgId, row.Id, ct);
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }

        return retracted;
    }

    /// <summary>
    /// Clears the reachability arm of every row for this version that <paramref name="asserted"/>
    /// does not name, and deletes any row left carrying nothing at all. The VEX arm is untouched,
    /// so a triage decision survives a SARIF that no longer reports the finding.
    ///
    /// <para>Named is decided by <see cref="SbomVulnKeyComparer"/>, the rule the writer resolved
    /// its conflict key by, so the sweep recognises the rows this request's own log just
    /// annotated whatever case it cited them in.</para>
    ///
    /// <para>A manually triaged row IS a candidate here, and correctly so: every column this
    /// clears is SARIF-owned, and the VEX arm is untouched. The <c>updated_at</c> write is not
    /// SARIF-owned, so it is skipped on such a row — withdrawing a reachability verdict must not
    /// move the date shown beside the operator's name. See <see cref="UpsertSarifBatchAsync"/> for the
    /// ownership rule and what it costs.</para>
    /// </summary>
    /// <returns>How many rows had their reachability arm retracted.</returns>
    public async Task<int> RetractUnassertedSarifAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyCollection<AnalysisRowKey> asserted,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var keep = BuildKeepSet(asserted);
        await using var conn = await _db.OpenAsync(ct);
        var candidates = (await conn.QueryAsync<AnalysisIdRow>(new CommandDefinition(
            """
            SELECT id AS Id, purl_key AS PurlKey, vuln_key AS VulnKey
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
              AND (reachability IS NOT NULL OR confidence IS NOT NULL OR sarif_suppressed <> 0
                   OR security_severity IS NOT NULL OR severity_origin IS NOT NULL
                   OR fingerprint IS NOT NULL)
            """,
            new { orgId, projectVersionId },
            cancellationToken: ct))).ToList();

        int retracted = 0;
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var row in candidates)
            {
                if (keep.Contains((row.PurlKey, row.VulnKey)))
                {
                    continue;
                }

                await conn.ExecuteAsync(new CommandDefinition(
                    """
                    UPDATE project_vuln_analysis SET
                        reachability = NULL,
                        confidence = NULL,
                        sarif_suppressed = 0,
                        security_severity = NULL,
                        severity_origin = NULL,
                        fingerprint = NULL,
                        updated_at = CASE WHEN COALESCE(vex_source, '') = 'manual'
                                          THEN updated_at ELSE @now END
                    WHERE id = @id AND org_id = @orgId
                    """,
                    new { id = row.Id, orgId, now = now.ToUtcIso() },
                    dbTx,
                    cancellationToken: ct));
                retracted++;
                await DeleteIfEmptyAsync(conn, dbTx, orgId, row.Id, ct);
            }

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }

        return retracted;
    }

    /// <summary>
    /// Returns every component of this version to <c>dependency_scope = 'unknown'</c> except the
    /// ones <paramref name="namedComponentIds"/> lists. The scanner owns that column, so a
    /// component the current SARIF reports nothing about has no scanner verdict — and 'unknown'
    /// is the honest answer, not the verdict a superseded log happened to leave behind. 'unknown'
    /// is also the safe answer under the derived filters: it reads as production, so the
    /// component stays visible rather than quietly dropping out of the prod view.
    /// </summary>
    /// <returns>How many components were reset.</returns>
    public async Task<int> ResetUnnamedDependencyScopeAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyCollection<string> namedComponentIds,
        CancellationToken ct = default)
    {
        var keep = new HashSet<string>(namedComponentIds, StringComparer.Ordinal);
        await using var conn = await _db.OpenAsync(ct);
        var scoped = (await conn.QueryAsync<string>(new CommandDefinition(
            """
            SELECT id FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @projectVersionId
              AND dependency_scope <> 'unknown'
            """,
            new { orgId, projectVersionId },
            cancellationToken: ct))).ToList();

        int reset = 0;
        foreach (string componentId in scoped)
        {
            if (keep.Contains(componentId))
            {
                continue;
            }

            await conn.ExecuteAsync(new CommandDefinition(
                """
                UPDATE sbom_components SET dependency_scope = 'unknown'
                WHERE id = @componentId AND org_id = @orgId
                """,
                new { componentId, orgId },
                cancellationToken: ct));
            reset++;
        }

        return reset;
    }

    // A row exists to carry facts. Once both arms are empty it carries none, and leaving it would
    // accumulate one dead row per statement any document ever made about this version.
    private static Task DeleteIfEmptyAsync(
        DbConnection conn, DbTransaction dbTx, string orgId, string id, CancellationToken ct) =>
        conn.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM project_vuln_analysis
            WHERE id = @id AND org_id = @orgId
              AND vex_state IS NULL AND vex_source IS NULL AND vex_justification IS NULL
              AND vex_response IS NULL AND vex_detail IS NULL
              AND reachability IS NULL AND confidence IS NULL AND sarif_suppressed = 0
              AND security_severity IS NULL AND severity_origin IS NULL AND fingerprint IS NULL
            """,
            new { id, orgId },
            dbTx,
            cancellationToken: ct));

    // The asserted keys as both sweeps match them: purl_key ordinally, vuln_key case-insensitively,
    // through the one comparer every reader of the pair already shares.
    private static HashSet<(string PurlKey, string VulnKey)> BuildKeepSet(
        IReadOnlyCollection<AnalysisRowKey> asserted) =>
        new(asserted.Select(key => (key.PurlKey, key.VulnKey)), SbomVulnKeyComparer.Instance);

    private sealed class AnalysisIdRow
    {
        public string Id { get; set; } = "";
        public string PurlKey { get; set; } = "";
        public string VulnKey { get; set; } = "";
    }

    /// <summary>
    /// Resolves the actor discriminator for an audit write: a token whose subject is a user row
    /// in this tenant is a user actor, and one whose subject is a service token is a service
    /// actor carrying the token's name as its label. Written here rather than derived from the
    /// authentication scheme because a personal access token authenticates on the same scheme a
    /// CI token does, and labelling a user's upload as a service actor writes an actor id the
    /// service-token join can never resolve.
    /// </summary>
    public async Task<(string Kind, string? Label)> ResolveActorAsync(
        string orgId, string actorId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string? userId = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT id FROM users WHERE id = @actorId AND tenant_id = @orgId",
            new { actorId, orgId },
            cancellationToken: ct));
        if (userId is not null)
        {
            return (ActorKinds.User, null);
        }

        string? tokenName = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT name FROM service_tokens WHERE id = @actorId AND org_id = @orgId",
            new { actorId, orgId },
            cancellationToken: ct));
        return tokenName is not null ? (ActorKinds.Service, tokenName) : (ActorKinds.User, null);
    }
}
