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
/// CISA D2 (SBOM Author Signature): <c>DependablyExportProperties.SignatureState</c>'s value —
/// emitted at <c>dependably:signature-state</c> — is a closed three-member vocabulary,
/// <see cref="SbomAuthorSigner.SignedState"/>/<see cref="SbomAuthorSigner.UnsignedNoMasterKeyState"/>/
/// <see cref="SbomAuthorSigner.UnsignedKeyUnavailableState"/>, never a fourth spelling invented at
/// a call site.
///
/// <para><b>Enforced from the emitted side, not by scanning source for a literal</b> — the same
/// posture <c>UnknownWithheldVocabularyComplianceTests</c> takes for the <c>-status</c>
/// vocabulary, and for the identical reason: a source-regex gate is blind to a call site that
/// spells a passing value ("Signed", "unsigned") that only LOOKS like one of the three. This gate
/// instead drives <see cref="SbomExportService"/> through all three REACHABLE production code
/// paths — a signer that can mint and read the org's own key, one with no master key configured at
/// all, and one that cannot read a key another replica already minted for the same org — and
/// checks the rendered <c>dependably:signature-state</c> property against the closed set every
/// time. It is deliberately a SIBLING of the <c>-status</c> gate rather than a widened selector on
/// it: <c>-status</c>'s allowed set is <c>{unknown, withheld}</c>, and <c>signed</c> is not a
/// member of it — merging the two selectors would either reject every legitimate
/// <c>signature-state</c> value or silently admit <c>unknown</c>/<c>withheld</c> as if they were
/// valid signature states, neither of which is the invariant either gate exists to hold.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class SignatureStateVocabularyComplianceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly ITestOutputHelper _output;

    public SignatureStateVocabularyComplianceTests(InMemoryDbFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    private SbomExportService ExportService(SbomAuthorSigner signer)
    {
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        return new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, signer);
    }

    private async Task<(string OrgId, string ProjectId, string VersionId)> SeedProjectVersionAsync(string slug)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"{slug}-{Guid.NewGuid():N}"[..24]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'sig-state-app', 'application', @now)
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
                (@id, @orgId, @versionId, 'pkg:npm/sig-state-widget@1.0.0', 'npm', 'sig-state-widget', '1.0.0',
                 'sig-state-widget', 'library', 'direct', @now)
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });

        return (orgId, projectId, versionId);
    }

    /// <summary>
    /// Recursively walks the whole document tree — <c>dependably:signature-state</c> lives inside
    /// <c>metadata.properties</c>, at a fixed depth for a per-project export but not one this
    /// gate should hard-code, since it must keep working against the collection renderer's own
    /// <c>metadata.properties</c> without change — collecting every property object whose name is
    /// exactly <see cref="DependablyExportProperties.SignatureState"/>.
    /// </summary>
    private static void CollectSignatureStateProperties(JsonElement element, List<string?> found)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                if (element.TryGetProperty("name", out var nameEl) && nameEl.ValueKind == JsonValueKind.String
                    && string.Equals(nameEl.GetString(), DependablyExportProperties.SignatureState, StringComparison.Ordinal)
                    && element.TryGetProperty("value", out var valueEl))
                {
                    found.Add(valueEl.ValueKind == JsonValueKind.String ? valueEl.GetString() : null);
                }

                foreach (var prop in element.EnumerateObject())
                {
                    CollectSignatureStateProperties(prop.Value, found);
                }

                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectSignatureStateProperties(item, found);
                }

                break;
        }
    }

    /// <summary>
    /// Drives all three states from real production code paths — never a hand-built JSON
    /// fixture — and checks every rendered <c>dependably:signature-state</c> value against the
    /// closed set. A fourth value appearing on any of the three renders (the shape a mutant
    /// inventing a new spelling, or widening <see cref="SbomAuthorSigner"/>'s vocabulary without
    /// updating this gate, would take) fails here.
    /// </summary>
    [Fact]
    public async Task EveryRenderedSignatureStateIsAMemberOfTheClosedVocabulary()
    {
        var found = new List<string?>();

        // State 1: signed — a replica with DEPENDABLY_MASTER_KEY configured, minting the org's
        // first key.
        var (signedOrgId, signedProjectId, signedVersionId) = await SeedProjectVersionAsync("sig-signed");
        var signedExport = ExportService(TestSbomAuthorSigner.Configured(_fixture.Store, _clock));
        string signedJson = (await signedExport.BuildSbomDocumentAsync(
            signedOrgId, signedProjectId, signedVersionId, SbomExportOptions.Default, CancellationToken.None))!;
        CollectSignatureStateProperties(JsonDocument.Parse(signedJson).RootElement, found);

        // State 2: unsigned-no-master-key — a replica with no master key at all, for an org that
        // has never had one minted.
        var (unconfiguredOrgId, unconfiguredProjectId, unconfiguredVersionId) = await SeedProjectVersionAsync("sig-unconfigured");
        var unconfiguredExport = ExportService(TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
        string unconfiguredJson = (await unconfiguredExport.BuildSbomDocumentAsync(
            unconfiguredOrgId, unconfiguredProjectId, unconfiguredVersionId, SbomExportOptions.Default, CancellationToken.None))!;
        CollectSignatureStateProperties(JsonDocument.Parse(unconfiguredJson).RootElement, found);

        // State 3: unsigned-key-unavailable — a replica with no master key of its own reading an
        // org whose active key was minted by ANOTHER replica (the mixed-fleet/rolling-rollout
        // shape) sharing the same store.
        var (mixedOrgId, mixedProjectId, mixedVersionId) = await SeedProjectVersionAsync("sig-mixed-fleet");
        var mintingSigner = TestSbomAuthorSigner.Configured(_fixture.Store, _clock);
        var (mintedKey, _, _) = await mintingSigner.ResolveAsync(mixedOrgId, CancellationToken.None);
        mintedKey?.Dispose();
        var keyUnavailableExport = ExportService(TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
        string keyUnavailableJson = (await keyUnavailableExport.BuildSbomDocumentAsync(
            mixedOrgId, mixedProjectId, mixedVersionId, SbomExportOptions.Default, CancellationToken.None))!;
        CollectSignatureStateProperties(JsonDocument.Parse(keyUnavailableJson).RootElement, found);

        foreach (string? value in found)
        {
            _output.WriteLine($"dependably:signature-state = \"{value}\"");
        }

        // The fixture is built specifically to exercise all three reachable states; fewer than
        // three renders found would make the vocabulary assertion below vacuously narrow.
        Assert.True(found.Count == 3, $"Expected exactly 3 rendered dependably:signature-state properties (one per driven state), found {found.Count}.");

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            SbomAuthorSigner.SignedState,
            SbomAuthorSigner.UnsignedNoMasterKeyState,
            SbomAuthorSigner.UnsignedKeyUnavailableState,
        };
        var violations = found.Where(v => v is null || !allowed.Contains(v)).ToList();
        Assert.True(
            violations.Count == 0,
            "A dependably:signature-state property was emitted with a value outside {signed, unsigned-no-master-key, unsigned-key-unavailable}: "
            + string.Join(", ", violations));

        // Each of the three fixture scenarios is built to reach a DIFFERENT state — asserting all
        // three actually appeared (not just three renders of the SAME state) is what makes this a
        // real coverage claim rather than an accident of which branch the fixture happened to hit
        // three times.
        Assert.Equal(
            allowed,
            found.Where(v => v is not null).Select(v => v!).ToHashSet(StringComparer.Ordinal));
    }
}
