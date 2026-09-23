namespace Dependably.Protocol.Provenance;

/// <summary>
/// Per-ecosystem trust-anchor configuration snapshot for a single org: whether each ecosystem's
/// provenance verifier has at least one anchor pinned. <c>OrgSettingsController</c>'s
/// proxy-settings endpoint and <c>PolicyController</c>'s policy summary both read this, so the
/// two surfaces report anchor configuration from one source of truth rather than each computing
/// it independently.
/// </summary>
public sealed record ProvenanceAnchorStatus(
    bool Npm, bool NuGet, bool PyPi, bool Rpm, bool Maven, bool Terraform);

/// <summary>
/// Resolves <see cref="ProvenanceAnchorStatus"/> for an org by querying the six per-ecosystem
/// artefact-provenance verifiers. SBOM author-signature anchors are out of scope —
/// <see cref="Dependably.Infrastructure.Sbom.SbomSignatureVerifier"/> lives in the management
/// assembly and is an upload-admission concern, not a <c>BlockGateService</c> arm; a caller that
/// needs it queries it directly.
/// </summary>
public sealed class ProvenanceAnchorStatusResolver
{
    private readonly NpmProvenanceVerifier _npm;
    private readonly NuGetProvenanceVerifier _nuget;
    private readonly PyPiProvenanceVerifier _pypi;
    private readonly RpmProvenanceVerifier _rpm;
    private readonly MavenProvenanceVerifier _maven;
    private readonly TerraformProvenanceVerifier _terraform;

    public ProvenanceAnchorStatusResolver(
        NpmProvenanceVerifier npm,
        NuGetProvenanceVerifier nuget,
        PyPiProvenanceVerifier pypi,
        RpmProvenanceVerifier rpm,
        MavenProvenanceVerifier maven,
        TerraformProvenanceVerifier terraform)
    {
        _npm = npm;
        _nuget = nuget;
        _pypi = pypi;
        _rpm = rpm;
        _maven = maven;
        _terraform = terraform;
    }

    public async Task<ProvenanceAnchorStatus> ResolveAsync(string orgId, CancellationToken ct = default) =>
        new(
            Npm: await _npm.IsConfiguredForAsync(orgId, ct),
            NuGet: await _nuget.IsConfiguredForAsync(orgId, ct),
            PyPi: await _pypi.IsConfiguredForAsync(orgId, ct),
            Rpm: await _rpm.IsConfiguredForAsync(orgId, ct),
            Maven: await _maven.IsConfiguredForAsync(orgId, ct),
            Terraform: await _terraform.IsConfiguredForAsync(orgId, ct));
}
