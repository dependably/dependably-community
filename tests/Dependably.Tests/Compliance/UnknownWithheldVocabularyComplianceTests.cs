using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// CISA P4a/X4: dependably's two-state "unknown to the author" vs "withheld by the author"
/// absence vocabulary — <c>DependablyExportProperties.UnknownValue</c>/<c>WithheldValue</c> — is
/// the only vocabulary a <c>*-status</c> property may hold.
///
/// <para><b>Enforced from the emitted side, not by scanning source for a literal.</b> A
/// source-regex gate bans the spelling this test's own predecessor happened to use
/// (<c>"unknown"</c>/<c>"withheld"</c> as a bare string) and is blind to a site that invents a
/// THIRD spelling entirely — <c>"not-stated"</c>, <c>"UNKNOWN"</c> — because neither literal it
/// looks for ever appears at that call site. That is exactly the shape the acceptance criterion
/// names: "a test asserts no site invents its own spelling." This gate instead renders real
/// documents through <see cref="SbomExportService"/> and walks every emitted
/// <c>{"name": …, "value": …}</c> property object in the tree, checking the VALUE of every
/// property whose NAME ends in <c>-status</c> (the naming convention every one of the six
/// "indicate unknown" duty properties follows —
/// <see cref="DependablyExportProperties.ProducerStatus"/>,
/// <see cref="DependablyExportProperties.VersionStatus"/>,
/// <see cref="DependablyExportProperties.HashStatus"/>,
/// <see cref="DependablyExportProperties.LicenseStatus"/>,
/// <see cref="DependablyExportProperties.ToolVersionStatus"/>,
/// <see cref="DependablyExportProperties.IdentifierStatus"/>) against the closed
/// <c>{unknown, withheld}</c> set. This is enforceable regardless of which source file the
/// emission lives in, and does not depend on — or get fooled by — doc-comment prose that happens
/// to contain the words "unknown" or "withheld".</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class UnknownWithheldVocabularyComplianceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomExportService _export;
    private readonly ITestOutputHelper _output;

    public UnknownWithheldVocabularyComplianceTests(InMemoryDbFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    /// <summary>
    /// Seeds one project version deliberately triggering every one of the five duty sites at
    /// once: a component with no producer, no version/versionRange, no hash of any kind and no
    /// licence (D10e/D12a/D14d/D16e), plus an original tool named with no version (D8b).
    /// </summary>
    private async Task<(string OrgId, string ProjectId, string VersionId)> SeedDocumentTriggeringEveryDutyAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"vocab-{Guid.NewGuid():N}"[..20]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'app', 'application', @now)
            """,
            new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_kind, created_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/bare@0', 'npm', 'bare', NULL, 'bare',
                 'library', 'direct', @now)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, spec_version, blob_key,
                 sha256, size_bytes, tool_name, tool_version, uploaded_at)
            VALUES
                (@id, @orgId, @versionId, 'sbom', 'cyclonedx-json', '1.6', 'blobkey',
                 'deadbeef', 10, 'cyclonedx-npm', NULL, @now)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });

        return (orgId, projectId, versionId);
    }

    [Fact]
    public async Task EveryEmittedStatusPropertyValueIsAMemberOfTheDefinedVocabulary()
    {
        var (orgId, projectId, versionId) = await SeedDocumentTriggeringEveryDutyAsync();

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;

        var statusProperties = new List<(string Name, string? Value)>();
        CollectStatusProperties(JsonDocument.Parse(json).RootElement, statusProperties);

        // The fixture is built specifically to exercise every duty site; a fixture that emits
        // nothing to check would make the assertion below vacuously true and prove nothing.
        Assert.True(
            statusProperties.Count >= 5,
            $"Expected at least 5 *-status properties from a document triggering every duty site, found {statusProperties.Count}.");

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            DependablyExportProperties.UnknownValue, DependablyExportProperties.WithheldValue,
        };
        var violations = statusProperties.Where(p => p.Value is null || !allowed.Contains(p.Value)).ToList();

        foreach (var (name, value) in statusProperties)
        {
            _output.WriteLine($"{name} = \"{value}\"");
        }

        Assert.True(
            violations.Count == 0,
            "A *-status property was emitted with a value outside {unknown, withheld}: "
            + string.Join(", ", violations.Select(v => $"{v.Name}=\"{v.Value}\"")));
    }

    /// <summary>
    /// Recursively walks the whole document tree — <c>properties[]</c> arrays live at several
    /// unrelated nesting depths (document metadata, a component, a tool entry inside
    /// <c>metadata.tools.components[]</c>) — collecting every <c>{"name","value"}</c> property
    /// object whose name ends in <c>-status</c>.
    /// </summary>
    private static void CollectStatusProperties(JsonElement element, List<(string Name, string? Value)> found)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                if (element.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String
                    && element.TryGetProperty("value", out var valueEl))
                {
                    string? name = nameEl.GetString();
                    if (name is not null && name.EndsWith("-status", StringComparison.Ordinal))
                    {
                        found.Add((name, valueEl.ValueKind == JsonValueKind.String ? valueEl.GetString() : null));
                    }
                }

                foreach (var prop in element.EnumerateObject())
                {
                    CollectStatusProperties(prop.Value, found);
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectStatusProperties(item, found);
                }

                break;
        }
    }
}
