using Dependably.Infrastructure;
using Dependably.Protocol.Provenance;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Per-org signature trust anchors, surfaced under Settings → Security. Each ecosystem
/// owns a flat list of anchors; the per-ecosystem verifier resolves all rows at request
/// time and accepts a signature verified by any of them.
///
/// <c>material</c> is PUBLIC key material (PGP public keys, X.509 certs, SPKI DER base64,
/// Sigstore roots, Rekor keys, issuer/subject JSON) and is stored plaintext. It is write-only
/// over the API: no response — neither the list nor the add-confirmation entry — returns
/// <c>material</c>; the derived <c>key_id</c> is what surfaces for display.
///
/// The accepted <c>(ecosystem, anchor_kind)</c> pairs are
/// <see cref="Dependably.Infrastructure.TrustAnchorPairs.Registered"/>; the material validator
/// behind each pair is registered in <see cref="EcosystemValidators"/>. RPM is the reference
/// implementation: parses the material as an OpenPGP public key ring at insert time and derives
/// <c>key_id</c> from the first key's fingerprint. Each sibling ecosystem adds its own arm to
/// that dictionary and its pair to the shared set.
/// </summary>
[ApiController]
[Authorize]
public sealed class TrustAnchorController : OrgScopedControllerBase
{
    private readonly TrustAnchorRepository _anchors;
    private readonly IPerOrgTrustAnchorStore _store;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly ILogger<TrustAnchorController> _logger;

    public TrustAnchorController(
        TrustAnchorRepository anchors,
        IPerOrgTrustAnchorStore store,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        ILogger<TrustAnchorController> logger)
    {
        _anchors = anchors;
        _store = store;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _logger = logger;
    }

    // Per-ecosystem material validators. Each entry validates the raw material string and
    // returns either a (keyId, error) pair: keyId is non-null on success; error is non-null
    // on failure. The keyId is derived from the material (e.g. PGP fingerprint) and stored
    // in the key_id column; callers may also supply a keyId override in the request which
    // takes precedence for display-only purposes.
    //
    // Keyed by (ecosystem, anchorKind). The accepted pair set itself lives in
    // TrustAnchorPairs.Registered, which the audit surfaces read too, so the insert gate and the
    // "this stored row was never validated" report cannot disagree. This dictionary supplies the
    // validator behind each of those pairs and is pinned to cover exactly that set by
    // TrustAnchorPairsTests. Add an arm here — and the matching pair there — when a new ecosystem
    // lands its reference implementation.
    internal static readonly Dictionary<(string Ecosystem, string AnchorKind), Func<string, ILogger, (string? KeyId, string? Error)>>
        EcosystemValidators = new()
        {
            [("rpm", "pgp")] = ValidateRpmPgpMaterial,
            [("maven", "pgp")] = ValidateMavenPgpMaterial,
            [("terraform", "pgp")] = ValidateTerraformPgpMaterial,
            [("npm", "spki")] = ValidateNpmSpkiMaterial,
            [("nuget", "x509")] = ValidateNuGetX509Material,
            [("pypi", "sigstore_root")] = ValidatePyPiSigstoreRootMaterial,
            [("pypi", "trusted_publisher")] = ValidatePyPiTrustedPublisherMaterial,
            [("pypi", "rekor_key")] = ValidatePyPiRekorKeyMaterial,
            [("apk", "rsa")] = ValidateApkRsaMaterial,
        };

    // Per-ecosystem material normalizers. Called before validation to transform the raw material
    // into a canonical form for storage. Returns the normalized material on success, or an error
    // string on failure. Only entries that need normalization (e.g. trusted_publisher, which
    // adds an explicit match field) need to be registered here.
    private static readonly Dictionary<(string Ecosystem, string AnchorKind), Func<string, (string? Normalized, string? Error)>>
        MaterialNormalizers = new()
        {
            [("pypi", "trusted_publisher")] = NormalizePyPiTrustedPublisher,
        };

    // Normalizes a PyPI trusted_publisher material string: validates the JSON, applies the
    // smart match-mode default when absent, and always stores the mode explicitly. Returns
    // the normalized JSON (with match always present) on success, or an error on failure.
    private static (string? Normalized, string? Error) NormalizePyPiTrustedPublisher(string material)
    {
        var (normalized, error) =
            Protocol.Provenance.PyPiSigstoreTrustStore.ValidateTrustedPublisherMaterial(material);
        return (normalized, error);
    }

    // RPM validator: parses the material as an ASCII-armored OpenPGP public key ring and
    // derives the key_id from the first key's fingerprint. Rejects malformed or empty pastes.
    private static (string? KeyId, string? Error) ValidateRpmPgpMaterial(string material, ILogger logger)
        => ValidatePgpMaterial(material, logger, "rpm");

    // Maven validator: same PGP public key ring validation as RPM — armored PGP block,
    // key_id derived from the first key's fingerprint.
    private static (string? KeyId, string? Error) ValidateMavenPgpMaterial(string material, ILogger logger)
        => ValidatePgpMaterial(material, logger, "maven");

    // Terraform validator: same PGP public key ring validation as RPM/Maven — armored PGP block,
    // key_id derived from the first key's fingerprint. Pins the publisher key that signs a
    // provider registry's SHASUMS file, not the upstream-supplied signing_keys from the download
    // response.
    private static (string? KeyId, string? Error) ValidateTerraformPgpMaterial(string material, ILogger logger)
        => ValidatePgpMaterial(material, logger, "terraform");

    // Shared PGP material validator used by both RPM and Maven. Parses the material as an
    // ASCII-armored OpenPGP public key ring and derives the key_id from the first fingerprint.
    private static (string? KeyId, string? Error) ValidatePgpMaterial(
        string material, ILogger logger, string ecosystem)
    {
        var bundle = PgpKeyRingBuilder.TryParse(material, logger, $"{ecosystem}/validate");
        if (bundle is null)
        {
            return (null, "material could not be parsed as an OpenPGP public key block. " +
                         "Paste an ASCII-armored PGP public key (-----BEGIN PGP PUBLIC KEY BLOCK-----).");
        }

        string? fingerprint = PgpKeyRingBuilder.FirstFingerprint(bundle);
        return (fingerprint, null);
    }

    // npm SPKI validator: parses the material as a base64 SubjectPublicKeyInfo (SPKI) DER blob
    // and validates it as an ECDSA public key. The caller must supply a keyId (npm keyids look
    // like SHA256:jl3bwswu80Pj…; the colon is valid in a column value). Rejects malformed blobs.
    private static (string? KeyId, string? Error) ValidateNpmSpkiMaterial(string material, ILogger logger)
    {
        if (!Protocol.Provenance.NpmSignatureKeyStore.TryParseSpki(
                "validate", material, out _, logger))
        {
            return (null, "material could not be parsed as a base64 ECDSA SPKI public key. " +
                         "Paste the base64-encoded SubjectPublicKeyInfo (SPKI) DER from the npm registry's " +
                         "/-/npm/v1/keys response.");
        }

        // The key_id must be supplied by the caller for npm, for example a SHA-256 key
        // identifier string, since it is not derivable from the SPKI bytes alone the way PGP
        // fingerprints are. Returning null here lets the caller's keyId field take precedence.
        return (null, null);
    }

    // NuGet X.509 validator: parses the material as a PEM block or raw base64 DER X.509
    // certificate and derives key_id from the certificate's SHA-256 thumbprint. Rejects
    // content that does not parse as a certificate with a descriptive error.
    private static (string? KeyId, string? Error) ValidateNuGetX509Material(string material, ILogger logger)
    {
        string? keyId = Protocol.Provenance.NuGetSignatureTrustStore.DeriveKeyId(material, logger);
        if (keyId is null)
        {
            return (null, "material could not be parsed as an X.509 certificate. " +
                         "Paste a PEM block (-----BEGIN CERTIFICATE-----) or raw base64 DER. " +
                         "Add the nuget.org repository-signing root or intermediate(s) " +
                         "after verifying them out of band.");
        }

        return (keyId, null);
    }

    // PyPI sigstore_root validator: parses the material as a PEM block or raw base64 DER X.509
    // certificate and derives key_id from the certificate's SHA-256 thumbprint. These are the
    // Fulcio/Sigstore CA anchors the Fulcio-issued leaf must chain to.
    private static (string? KeyId, string? Error) ValidatePyPiSigstoreRootMaterial(string material, ILogger logger)
    {
        string? keyId = Protocol.Provenance.PyPiSigstoreTrustStore.DeriveRootKeyId(material, logger);
        if (keyId is null)
        {
            return (null, "material could not be parsed as an X.509 certificate. " +
                         "Paste a PEM block (-----BEGIN CERTIFICATE-----) or raw base64 DER. " +
                         "Add a Sigstore/Fulcio root or intermediate CA certificate " +
                         "after verifying it out of band.");
        }

        return (keyId, null);
    }

    // PyPI trusted_publisher validator: after normalization the material is already a well-formed
    // JSON object with issuer, subject, and match fields (normalization ran first via
    // MaterialNormalizers). This validator does a final parse check and returns null key_id
    // (trusted_publisher rows have no key_id — the identity is in the material JSON itself).
    private static (string? KeyId, string? Error) ValidatePyPiTrustedPublisherMaterial(
        string material, ILogger _)
    {
        var (_, error) =
            Protocol.Provenance.PyPiSigstoreTrustStore.ValidateTrustedPublisherMaterial(material);
        return error is not null ? (null, error) : (null, null);
    }

    // PyPI rekor_key validator: parses the material as a PEM block or raw base64 DER ECDSA SPKI
    // and derives key_id as the base64 SHA-256(SPKI). This is the Rekor transparency-log public
    // key used to verify the Signed Entry Timestamp on each bundle. Rekor keys are optional —
    // when present, inclusion-proof + SET + valid-at-signing verification is enforced on all
    // attestations for this org.
    private static (string? KeyId, string? Error) ValidatePyPiRekorKeyMaterial(string material, ILogger logger)
    {
        string? keyId = Protocol.Provenance.PyPiSigstoreTrustStore.DeriveRekorKeyId(material, logger);
        if (keyId is null)
        {
            return (null, "material could not be parsed as an ECDSA P-256 SPKI public key. " +
                         "Paste a PEM block (-----BEGIN PUBLIC KEY-----) or raw base64 DER SPKI. " +
                         "Add the Rekor transparency-log public key after verifying it out of band.");
        }

        return (keyId, null);
    }

    // apk validator: parses the material as a PEM-encoded RSA public key (SPKI
    // "-----BEGIN PUBLIC KEY-----" or PKCS#1 "-----BEGIN RSA PUBLIC KEY-----") and derives
    // key_id as "SHA256:" followed by the base64 SHA-256 digest of the SPKI DER, the same
    // convention npm registry keyids use. Rejects malformed material or a non-RSA key.
    private static (string? KeyId, string? Error) ValidateApkRsaMaterial(string material, ILogger logger)
    {
        string? keyId = Protocol.Provenance.ApkTrustAnchorKeyStore.DeriveKeyId(material, logger);
        if (keyId is null)
        {
            return (null, "material could not be parsed as an RSA public key. " +
                         "Paste a PEM block (-----BEGIN PUBLIC KEY-----) with SPKI-encoded RSA key material — " +
                         "the key named in the .SIGN.RSA.<keyname> entry inside a signed APKINDEX.tar.gz.");
        }

        return (keyId, null);
    }

    /// <summary>GET /api/v1/trust-anchors — list anchors for the caller's org.</summary>
    [HttpGet("api/v1/trust-anchors")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (result is not null)
        {
            return result;
        }

        var entries = await _anchors.ListAsync(CurrentTenantId(), ct);
        return Ok(entries);
    }

    /// <summary>POST /api/v1/trust-anchors — add a trust anchor.</summary>
    [HttpPost("api/v1/trust-anchors")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Add([FromBody] AddTrustAnchorRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string ecosystem = req.Ecosystem?.Trim().ToLowerInvariant() ?? "";
        if (!TrustAnchorRepository.IsSupportedEcosystem(ecosystem))
        {
            return _problems.ValidationErrorActionKey("ecosystem", "error.common.mustBeOneOf", string.Join(", ", TrustAnchorRepository.SupportedEcosystems));
        }

        string anchorKind = req.AnchorKind?.Trim().ToLowerInvariant() ?? "";
        if (!TrustAnchorRepository.IsAllowedAnchorKind(anchorKind))
        {
            return _problems.ValidationErrorActionKey("anchorKind", "error.common.mustBeOneOf", string.Join(", ", TrustAnchorRepository.AllowedAnchorKinds));
        }

        // Reject any (ecosystem, anchorKind) combination outside TrustAnchorPairs.Registered
        // before any material handling. An unregistered pair has no material validator, so
        // accepting one stores arbitrary bytes as a signature trust root — and, for the five
        // ecosystems whose IsConfiguredFor check tests only for row presence, makes a
        // verify_*_signatures='block' policy read as backed while nothing can verify.
        // Every ecosystem in TrustAnchorRepository.SupportedEcosystems has at least one
        // registered anchorKind, so the allowed-list below is never empty for a valid ecosystem.
        if (!TrustAnchorPairs.IsRegistered(ecosystem, anchorKind))
        {
            return _problems.ValidationErrorActionKey(
                "anchorKind", "error.trustAnchor.unsupportedAnchorKindForEcosystem",
                anchorKind, ecosystem, string.Join(", ", TrustAnchorPairs.AnchorKindsFor(ecosystem)));
        }

        string? material = req.Material?.Trim();
        if (string.IsNullOrEmpty(material))
        {
            return _problems.ValidationErrorActionKey("material", "error.trustAnchor.materialEmpty");
        }

        string orgId = CurrentTenantId();
        string? label = string.IsNullOrWhiteSpace(req.Label) ? null : req.Label.Trim();
        string? keyId = string.IsNullOrWhiteSpace(req.KeyId) ? null : req.KeyId.Trim();

        // Apply per-ecosystem material normalizers before validation. Normalizers transform the
        // raw material into a canonical storage form (e.g. trusted_publisher always stores the
        // match field explicitly). A normalization error is reported as a 400 validation error.
        if (MaterialNormalizers.TryGetValue((ecosystem, anchorKind), out var normalize))
        {
            var (normalized, normalizeError) = normalize(material);
            if (normalizeError is not null)
            {
                return _problems.ValidationErrorAction("material", normalizeError);
            }
            material = normalized!;
        }

        // Run per-ecosystem material validation. The validator parses the material, rejects
        // invalid content with a 422-style 400, and derives the key_id (e.g. PGP fingerprint).
        // The caller-supplied keyId overrides the derived one when both are present.
        //
        // A registered pair always has a validator (TrustAnchorPairsTests pins the two sets
        // equal). An absent one denies rather than falling through, so a pair added to the
        // shared set without its validator can never store unvalidated material.
        if (!EcosystemValidators.TryGetValue((ecosystem, anchorKind), out var validate))
        {
            return _problems.ValidationErrorActionKey(
                "anchorKind", "error.trustAnchor.unsupportedAnchorKindForEcosystem",
                anchorKind, ecosystem, string.Join(", ", TrustAnchorPairs.AnchorKindsFor(ecosystem)));
        }

        var (derivedKeyId, validationError) = validate(material, _logger);
        if (validationError is not null)
        {
            return _problems.ValidationErrorAction("material", validationError);
        }
        keyId ??= derivedKeyId;

        // Minimum-strength floor, applied per anchor_kind once the material is known to parse.
        // A trust anchor bounds the strength of every signature verdict derived from it, so the
        // floor is a hard one rather than an opt-in — and it is enforced here, at import, where
        // the operator is present to act on the rejection. Anchors already stored keep verifying.
        string? strengthError = TrustAnchorKeyStrength.Validate(anchorKind, material);
        if (strengthError is not null)
        {
            return _problems.ValidationErrorAction("material", strengthError);
        }

        var entry = await _anchors.AddAsync(
            orgId, new NewTrustAnchor(ecosystem, anchorKind, material, keyId, label, GetUserId()), ct);
        _store.InvalidateTrustAnchorCache(orgId);

        await _audit.LogAsync(
            "trust_anchor_added", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            ecosystem: ecosystem,
            detail: System.Text.Json.JsonSerializer.Serialize(new
            {
                id = entry.Id,
                ecosystem,
                anchorKind,
                label,
                keyId,
            }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return CreatedAtAction(nameof(List), null, entry);
    }

    /// <summary>DELETE /api/v1/trust-anchors/{id} — remove a trust anchor.</summary>
    [HttpDelete("api/v1/trust-anchors/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        await _anchors.DeleteAsync(orgId, id, ct);
        _store.InvalidateTrustAnchorCache(orgId);

        await _audit.LogAsync(
            "trust_anchor_removed", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: System.Text.Json.JsonSerializer.Serialize(new { id }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }
}

/// <summary>Request body for adding a trust anchor.</summary>
public sealed record AddTrustAnchorRequest(
    string? Ecosystem,
    string? AnchorKind,
    string? Material,
    string? Label = null,
    string? KeyId = null);
