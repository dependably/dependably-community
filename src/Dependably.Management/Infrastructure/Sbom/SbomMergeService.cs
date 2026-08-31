using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure.Sbom;

/// <summary>How many statements or results one document bound, and how many found no component.</summary>
public sealed record SbomBindingCounts(int Total, int Applied, int Unmatched);

/// <summary>
/// What one VEX apply did: the counts the response reports, plus the exact set of analysis rows
/// the document asserted. The set is what makes retraction-by-omission possible — the caller
/// hands it back so every upload-sourced row outside it is cleared.
/// </summary>
public sealed record SbomVexApplication(
    SbomBindingCounts Counts, IReadOnlyCollection<AnalysisRowKey> Asserted);

/// <summary>
/// What one SARIF apply did: the counts, the analysis rows the log asserted, and the components
/// it carried a component-level fact for. Components outside that last set have no scanner
/// verdict under the current log and are returned to <c>dependency_scope = 'unknown'</c>.
/// </summary>
public sealed record SbomSarifApplication(
    SbomBindingCounts Counts,
    IReadOnlyCollection<AnalysisRowKey> Asserted,
    IReadOnlyCollection<string> NamedComponentIds);

/// <summary>
/// Turns a parsed document into rows: the component merge, the VEX arm and the reachability arm.
///
/// <para>Every method here is idempotent by construction, because ingest is defined as a
/// re-runnable merge rather than as a sequence of events: re-applying the same document produces
/// the same rows. That is what lets a re-uploaded SBOM re-run the version's stored VEX and SARIF
/// against the inventory it just wrote, with no separate replay mechanism. It does not relax the
/// upload order across document kinds — a project version is created by an SBOM upload alone, so
/// the SBOM for a version must land before its VEX or SARIF; both resolve read-only and answer
/// 404 against a version that does not exist yet, because accepting one would mean inventing a
/// version with no inventory to attach it to.</para>
///
/// <para>An unmatched statement is stored as its own analysis row rather than discarded. A VEX
/// asserting that a component is not affected is exactly as much a fact about the application
/// when this version's SBOM happens not to list that component, and dropping it would make the
/// upload silently lossy in the one direction a reader cannot detect.</para>
/// </summary>
public sealed class SbomMergeService
{
    private readonly SbomIngestRepository _ingest;

    public SbomMergeService(SbomIngestRepository ingest)
    {
        _ingest = ingest;
    }

    /// <summary>Replaces a version's inventory with the document's components.</summary>
    public Task<SbomComponentMergeCounts> MergeComponentsAsync(
        string orgId,
        string projectVersionId,
        CycloneDxDocument document,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var positions = SbomDependencyGraph.Resolve(document);
        var upserts = new List<SbomComponentUpsert>(document.Components.Count);

        foreach (var component in document.Components)
        {
            var identity = SbomPurlKey.TryParse(component.Purl);
            string? reference = component.BomRef ?? component.Purl;
            var position = reference is not null && positions.TryGetValue(reference, out var found)
                ? found
                : new SbomGraphPosition(null, null);

            upserts.Add(new SbomComponentUpsert(
                Purl: component.Purl,
                Ecosystem: identity?.Ecosystem,
                PurlName: identity?.Name,
                Version: identity?.Version ?? component.Version,
                Name: component.Name,
                ComponentType: component.Type,
                SbomScope: component.Scope,
                DependencyKind: position.Kind,
                DependencyPath: position.PathJson,
                LicenseSpdx: component.LicenseSpdx,
                Description: component.Description,
                ComponentAuthor: component.Author,
                Copyright: component.Copyright,
                ComponentGroup: component.Group,
                WebsiteUrl: component.WebsiteUrl,
                VcsUrl: component.VcsUrl,
                IssueTrackerUrl: component.IssueTrackerUrl,
                DistributionUrl: component.DistributionUrl,
                ComponentHashes: component.HashesJson));
        }

        return _ingest.MergeComponentsAsync(orgId, projectVersionId, upserts, now, ct);
    }

    /// <summary>
    /// Binds CycloneDX analysis statements — from a VEX document or from the vulnerabilities
    /// array embedded in an SBOM — onto the version's analysis rows.
    /// </summary>
    public async Task<SbomVexApplication> ApplyCycloneDxStatementsAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyList<CycloneDxAnalysisStatement> statements,
        string? actorId,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var index = await BuildIndexAsync(orgId, projectVersionId, ct);
        var asserted = new HashSet<AnalysisRowKey>();
        int applied = 0;
        int unmatched = 0;
        int total = 0;

        // The writes are collected first and handed to the repository as one batch. One write is
        // one (statement, component) pair, which is the unit the parser's
        // SbomDocumentLimits.MaxComponentStatements ceiling charges — so this list, the asserted
        // set below, and the rows they produce are all bounded by that one number. Issuing them
        // one at a time made the request open a connection per pair.
        var writes = new List<VexStatementWrite>();

        foreach (var statement in statements)
        {
            foreach (string product in statement.ProductRefs)
            {
                string? purlKey = ResolvePurlKey(product);
                if (purlKey is null)
                {
                    continue;
                }

                total++;
                writes.Add(new VexStatementWrite(
                    purlKey,
                    statement.VulnId,
                    VexVocabulary.NormalizeState(statement.State),
                    VexVocabulary.NormalizeJustification(statement.Justification),
                    VexVocabulary.NormalizeResponse(statement.Response),
                    statement.Detail));
                asserted.Add(new AnalysisRowKey(purlKey, statement.VulnId));

                if (index.ByPurlKey.Contains(purlKey))
                {
                    applied++;
                }
                else
                {
                    unmatched++;
                }
            }
        }

        await _ingest.UpsertVexBatchAsync(orgId, projectVersionId, writes, actorId, now, ct);
        return new SbomVexApplication(new SbomBindingCounts(total, applied, unmatched), asserted);
    }

    /// <summary>Binds OpenVEX statements, already normalized onto the CycloneDX vocabulary.</summary>
    public Task<SbomVexApplication> ApplyOpenVexStatementsAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyList<OpenVexStatement> statements,
        string? actorId,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var translated = statements
            .Select(s => new CycloneDxAnalysisStatement(
                s.VulnId, s.ProductRefs, s.State, s.Justification, Response: null, s.Detail))
            .ToList();
        return ApplyCycloneDxStatementsAsync(orgId, projectVersionId, translated, actorId, now, ct);
    }

    /// <summary>
    /// Writes a SARIF log's per-vulnerability facts to the analysis rows and its component-level
    /// facts to the matched component rows. A result whose purl names no component still gets an
    /// analysis row; it simply annotates no component.
    /// </summary>
    public async Task<SbomSarifApplication> ApplySarifAsync(
        string orgId,
        string projectVersionId,
        SarifDocument document,
        string? actorId,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        var index = await BuildIndexAsync(orgId, projectVersionId, ct);
        var facts = new Dictionary<string, SbomComponentFactWrite>(StringComparer.Ordinal);
        var asserted = new HashSet<AnalysisRowKey>();
        int applied = 0;
        int unmatched = 0;

        // Collected and written as one batch, for the reason the VEX arm above states.
        var writes = new List<SarifFactWrite>(document.Results.Count);

        foreach (var result in document.Results)
        {
            var identity = SbomPurlKey.TryParse(result.Purl);
            string purlKey = identity?.Key ?? result.RuleId;
            writes.Add(new SarifFactWrite(
                purlKey,
                result.RuleId,
                result.Reachability,
                result.Confidence,
                result.Suppressed,
                result.SecuritySeverity,
                result.SeverityOrigin,
                result.Fingerprint));
            asserted.Add(new AnalysisRowKey(purlKey, result.RuleId));

            string? componentId = MatchComponent(index, identity, result.MessageText);
            if (componentId is null)
            {
                unmatched++;
                continue;
            }

            applied++;
            facts[componentId] = BuildComponentFact(componentId, result, facts);
        }

        await _ingest.UpsertSarifBatchAsync(orgId, projectVersionId, writes, actorId, now, ct);
        await _ingest.ApplyComponentFactsAsync(orgId, [.. facts.Values], ct);
        return new SbomSarifApplication(
            new SbomBindingCounts(document.Results.Count, applied, unmatched),
            asserted,
            facts.Keys.ToList());
    }

    /// <summary>
    /// Clears the VEX arm of every upload-sourced row this version holds that
    /// <paramref name="asserted"/> does not name. Called once per ingest request with the union of
    /// everything that request asserted, never once per apply: an SBOM upload applies its own
    /// embedded statements and then re-applies the stored VEX, and sweeping after each would have
    /// the second apply retract the first one's rows.
    /// </summary>
    public Task<int> RetractUnassertedVexAsync(
        string orgId,
        string projectVersionId,
        IReadOnlyCollection<AnalysisRowKey> asserted,
        DateTimeOffset now,
        CancellationToken ct = default) =>
        _ingest.RetractUnassertedVexAsync(orgId, projectVersionId, asserted, now, ct);

    /// <summary>
    /// Clears the reachability arm of every row this version holds that <paramref name="asserted"/>
    /// does not name, and returns every component the log named no result for to
    /// <c>dependency_scope = 'unknown'</c>.
    /// </summary>
    public async Task RetractUnassertedSarifAsync(
        string orgId,
        string projectVersionId,
        SbomSarifApplication application,
        DateTimeOffset now,
        CancellationToken ct = default)
    {
        await _ingest.RetractUnassertedSarifAsync(
            orgId, projectVersionId, application.Asserted, now, ct);
        await _ingest.ResetUnnamedDependencyScopeAsync(
            orgId, projectVersionId, application.NamedComponentIds, ct);
    }

    // Several results can name one component — one per advisory found in it — and they carry the
    // same component-level facts. The first result that states a fact wins, and a later result
    // that omits it does not blank what an earlier one supplied.
    private static SbomComponentFactWrite BuildComponentFact(
        string componentId,
        SarifResult result,
        IReadOnlyDictionary<string, SbomComponentFactWrite> existing)
    {
        existing.TryGetValue(componentId, out var prior);
        string scope = result.DependencyScope ?? prior?.DependencyScope ?? "unknown";
        string? kind = result.DependencyKind ?? prior?.DependencyKind;
        string? path = result.DependencyPath.Count > 0
            ? JsonSerializer.Serialize(result.DependencyPath)
            : prior?.DependencyPath;
        return new SbomComponentFactWrite(componentId, scope, kind, path);
    }

    /// <summary>The lookup tables one document's binding pass needs, built once per pass.</summary>
    private sealed record ComponentIndex(
        IReadOnlySet<string> ByPurlKey,
        IReadOnlyDictionary<string, string> ByVersionedPurl,
        IReadOnlyDictionary<string, string> ByNameVersion);

    private async Task<ComponentIndex> BuildIndexAsync(
        string orgId, string projectVersionId, CancellationToken ct)
    {
        var rows = await _ingest.ListComponentsAsync(orgId, projectVersionId, ct);
        var byPurlKey = new HashSet<string>(StringComparer.Ordinal);
        var byVersionedPurl = new Dictionary<string, string>(StringComparer.Ordinal);
        var byNameVersion = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var row in rows)
        {
            var identity = SbomPurlKey.TryParse(row.Purl);
            if (identity is not null)
            {
                byPurlKey.Add(identity.Key);
                byVersionedPurl.TryAdd(SbomPurlKey.VersionedKey(identity), row.Id);
            }

            byNameVersion.TryAdd(SbomPurlKey.NameVersionKey(row.Name, row.Version), row.Id);
        }

        return new ComponentIndex(byPurlKey, byVersionedPurl, byNameVersion);
    }

    // purl first, because it is an identity rather than a label. The name@version fallback reads
    // the result message, which the reachability scanner writes as "name@version is vulnerable
    // to …" — worth trying, because a producer that omits the purl bag still names the package.
    private static string? MatchComponent(
        ComponentIndex index, SbomPurlIdentity? identity, string? messageText)
    {
        if (identity is not null
            && index.ByVersionedPurl.TryGetValue(SbomPurlKey.VersionedKey(identity), out string? byPurl))
        {
            return byPurl;
        }

        string? coordinate = TryReadCoordinate(messageText);
        return coordinate is not null
               && index.ByNameVersion.TryGetValue(coordinate, out string? byName)
            ? byName
            : null;
    }

    private static string? TryReadCoordinate(string? messageText)
    {
        if (string.IsNullOrWhiteSpace(messageText))
        {
            return null;
        }

        string head = messageText.Split(' ', 2)[0];
        int at = head.LastIndexOf('@');
        return at > 0 && at + 1 < head.Length
            ? SbomPurlKey.NameVersionKey(head[..at], head[(at + 1)..])
            : null;
    }

    // A statement's product is a bom-ref, which producers conventionally spell as a purl. When
    // it is not purl-shaped it is still the only identity the statement has, so it keys the row
    // verbatim rather than being dropped — the row then reads as unmatched, which is true.
    private static string? ResolvePurlKey(string product)
    {
        var identity = SbomPurlKey.TryParse(product);
        return identity?.Key ?? (string.IsNullOrWhiteSpace(product) ? null : product);
    }

}
