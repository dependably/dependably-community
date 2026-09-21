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
/// CISA D13c/D13d: the <c>dependably:identifier:*</c> property namespace is a CLOSED vocabulary of
/// exactly three kinds — <c>commit-hash</c> and <c>uuid</c> (CycloneDX defines no native component
/// field for either, so every asserted entry of each lands here) and <c>cpe</c> OVERFLOW (CycloneDX's
/// native <c>cpe</c> field is singular, so only the first asserted CPE fits there; a SECOND one —
/// real SPDX practice, a <c>cpe22Type</c> and a <c>cpe23Type</c> SECURITY ref side by side — has no
/// native home and lands here too, per D13d). SWHID and OmniBOR never reach this namespace: both
/// have native ARRAY component fields (<c>swhid</c>, <c>omniborId</c>) wide enough to hold every
/// asserted entry, so nothing about them ever overflows to a property.
///
/// <para><b>Enforced from the emitted side, not by scanning source for a literal</b> — the same
/// posture <see cref="UnknownWithheldVocabularyComplianceTests"/> takes and for the identical
/// reason: a source-regex gate is blind to a call site that passes the ingest-side "kind" string
/// straight through to the property name instead of routing it through
/// <see cref="DependablyExportProperties.IdentifierCommitHash"/>/
/// <see cref="DependablyExportProperties.IdentifierUuid"/> — a defect that is invisible in source
/// (both the correct code and the mutant compile and call <c>Prop(name, value)</c>) and only
/// observable in the rendered document. This gate renders a real document through
/// <see cref="SbomExportService"/> from a component whose <c>additional_identifiers</c> carries a
/// THIRD kind no code path recognises, and asserts that kind never surfaces under
/// <c>dependably:identifier:</c> with its own raw spelling.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class ComponentIdentifierVocabularyComplianceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomExportService _export;
    private readonly ITestOutputHelper _output;

    public ComponentIdentifierVocabularyComplianceTests(InMemoryDbFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    /// <summary>
    /// Seeds a purl-less component carrying every disclosed kind (commit-hash, uuid) plus a THIRD
    /// kind — <c>vendor-widget-tag</c> — that no parser this codebase ships ever writes but that a
    /// raw pass-through implementation would still turn into
    /// <c>dependably:identifier:vendor-widget-tag</c>.
    /// </summary>
    private async Task<(string OrgId, string ProjectId, string VersionId)> SeedDocumentAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"idvocab-{Guid.NewGuid():N}"[..24]);
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
                (id, org_id, project_version_id, name, component_type, dependency_kind,
                 additional_identifiers, created_at)
            VALUES
                (@id, @orgId, @versionId, 'no-purl-widget', 'library', 'direct', @additionalIdentifiers, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                versionId,
                additionalIdentifiers = JsonSerializer.Serialize(new object[]
                {
                    new { kind = "commit-hash", value = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1" },
                    new { kind = "uuid", value = "urn:uuid:550e8400-e29b-41d4-a716-446655440000" },
                    new { kind = "vendor-widget-tag", value = "should-never-surface" },
                }),
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        return (orgId, projectId, versionId);
    }

    [Fact]
    public async Task EveryEmittedIdentifierPropertyName_IsAMemberOfTheClosedVocabulary()
    {
        var (orgId, projectId, versionId) = await SeedDocumentAsync();

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;

        var identifierProperties = new List<(string Name, string? Value)>();
        CollectIdentifierProperties(JsonDocument.Parse(json).RootElement, identifierProperties);

        foreach (var (name, value) in identifierProperties)
        {
            _output.WriteLine($"{name} = \"{value}\"");
        }

        // The fixture asserts two recognised kinds; a run that found neither would make every
        // assertion below vacuously true.
        Assert.True(
            identifierProperties.Count >= 2,
            $"Expected at least 2 dependably:identifier:* properties from a component asserting commit-hash and uuid, found {identifierProperties.Count}.");

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            DependablyExportProperties.IdentifierCommitHash,
            DependablyExportProperties.IdentifierUuid,
            DependablyExportProperties.IdentifierCpe,
        };
        var violations = identifierProperties.Where(p => !allowed.Contains(p.Name)).ToList();

        Assert.True(
            violations.Count == 0,
            "A dependably:identifier:* property was emitted with a name outside the closed vocabulary: "
            + string.Join(", ", violations.Select(v => $"{v.Name}=\"{v.Value}\"")));

        // The unrecognised third kind must not have surfaced under ANY name — not even a raw
        // pass-through spelling this test's own allowlist would not catch.
        Assert.DoesNotContain(json, "vendor-widget-tag", StringComparison.Ordinal);
        Assert.DoesNotContain(json, "should-never-surface", StringComparison.Ordinal);

        // D13a: this component has NO purl but DOES carry other identifiers (commit-hash, uuid) —
        // identifier-status must NOT fire alongside them. Weakening the emission condition to
        // "purl is null" alone (dropping the "AND no additional identifiers" half) would make this
        // component carry both a real dependably:identifier:* property AND a positive "no
        // identifier is known" claim at once — self-contradictory, and invisible unless a test
        // checks a purl-less component that ALSO has identifiers, not just one with none at all.
        var component = JsonDocument.Parse(json).RootElement.GetProperty("components").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == "no-purl-widget");
        var properties = component.GetProperty("properties").EnumerateArray().ToList();
        Assert.DoesNotContain(
            properties, p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierStatus);
    }

    /// <summary>Recursively walks the whole document tree collecting every <c>{"name","value"}</c> property object whose name starts with <c>dependably:identifier:</c>.</summary>
    private static void CollectIdentifierProperties(JsonElement element, List<(string Name, string? Value)> found)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                if (element.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String
                    && element.TryGetProperty("value", out var valueEl))
                {
                    string? name = nameEl.GetString();
                    if (name is not null && name.StartsWith("dependably:identifier:", StringComparison.Ordinal))
                    {
                        found.Add((name, valueEl.ValueKind == JsonValueKind.String ? valueEl.GetString() : null));
                    }
                }

                foreach (var prop in element.EnumerateObject())
                {
                    CollectIdentifierProperties(prop.Value, found);
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectIdentifierProperties(item, found);
                }

                break;
        }
    }
}
