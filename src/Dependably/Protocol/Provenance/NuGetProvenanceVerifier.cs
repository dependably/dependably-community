using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Dependably.Infrastructure.Observability;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies the signature embedded in a proxied <c>.nupkg</c> against operator-pinned trust
/// anchors.
///
/// A signed NuGet package (the <c>.nupkg</c> is a ZIP) carries a <c>.signature.p7s</c> entry at
/// the archive root: a PKCS#7/CMS <see cref="SignedCms"/>. nuget.org applies a repository
/// signature (and packages may also carry an author signature). Verification has two independent
/// halves, both of which must hold for a <see cref="ProvenanceStatus.Verified"/> verdict:
///
/// <list type="number">
///   <item>The CMS signature must validate over its own signed content
///         (<see cref="SignedCms.CheckSignature"/> with <c>verifySignatureOnly: true</c>) — this
///         catches a tampered signature blob or a signer whose private key did not produce it.</item>
///   <item>At least one signer certificate must chain to an operator-pinned anchor
///         (<see cref="NuGetSignatureTrustStore"/>), evaluated with a custom root-trust
///         <see cref="X509Chain"/> so the OS/system roots are never implicitly trusted.</item>
/// </list>
///
/// The package-content binding (that the bytes match what was signed) is enforced separately and
/// earlier in the ingest pipeline by the upstream-supplied <c>packageHash</c> checksum re-verify in
/// <c>ProxyFetchService</c>; this verifier establishes the trust-anchor binding the checksum cannot.
///
/// Result mapping: a valid CMS signature chaining to a pinned anchor →
/// <see cref="ProvenanceStatus.Verified"/> (signer = the signing cert subject/thumbprint); no
/// <c>.signature.p7s</c> entry → <see cref="ProvenanceStatus.Unsigned"/>; a present-but-invalid
/// signature, an untrusted chain, or any malformed/oversized archive →
/// <see cref="ProvenanceStatus.Failed"/>. Never throws on bad input — a parse/crypto failure maps
/// to <see cref="ProvenanceStatus.Failed"/> so the proxy ingest path can fail closed.
///
/// The trust anchors are operator-pinned (<c>NuGet:SignatureCertificates</c>), never the
/// upstream-fetched package or the system certificate stores, mirroring the npm
/// <see cref="NpmProvenanceVerifier"/> and RPM GpgKey posture.
/// </summary>
public sealed class NuGetProvenanceVerifier : IArtifactProvenanceVerifier
{
    // The signature entry sits at the ZIP root with this exact name (NuGet signing spec).
    private const string SignatureEntryName = ".signature.p7s";

    // Bound the buffered read of the signature entry — a real .signature.p7s is a few KB; a
    // hostile archive declaring a multi-GB entry must not exhaust memory. 1 MB is generous.
    private const int MaxSignatureBytes = 1 * 1024 * 1024;

    private readonly NuGetSignatureTrustStore _trust;
    private readonly ILogger<NuGetProvenanceVerifier> _logger;

    public NuGetProvenanceVerifier(NuGetSignatureTrustStore trust, ILogger<NuGetProvenanceVerifier> logger)
    {
        _trust = trust;
        _logger = logger;
    }

    public string Ecosystem => "nuget";

    public bool IsConfigured => _trust.IsConfigured;

    /// <summary>
    /// Metadata-driven verification does not apply to NuGet: the signature lives inside the
    /// <c>.nupkg</c> bytes, not the registration metadata. The NuGet ingest path calls
    /// <see cref="VerifyPackageAsync"/> with the staged package stream instead. Returning
    /// <see cref="ProvenanceResult.NotApplicable"/> keeps the uniform interface usable for
    /// generic resolution without implying an unsigned/failed verdict.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    /// <summary>
    /// Verifies the signature embedded in the <c>.nupkg</c> stream. The stream is buffered to a
    /// seekable copy (ZIP central-directory reads require seeking) bounded by
    /// <paramref name="maxBytes"/>; a package larger than the cap maps to
    /// <see cref="ProvenanceStatus.Failed"/> rather than allocating without bound. Never throws.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out",
        Justification = "Prose comment explaining the unsigned/signed branch; not commented-out code.")]
    public async Task<ProvenanceResult> VerifyPackageAsync(Stream nupkg, long maxBytes, CancellationToken ct = default)
    {
        byte[]? signatureBytes;
        try
        {
            signatureBytes = await ExtractSignatureEntryAsync(nupkg, maxBytes, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Malformed/oversized ZIP, truncated read, etc. — fail closed.
            _logger.LogWarning(
                "NuGet signature extraction failed ({ExceptionType}); treating the package as unverifiable.",
                ex.GetType().Name);
            return Record(ProvenanceResult.Failed);
        }

        // No .signature.p7s entry → the package is unsigned (older packages predate signing);
        // otherwise verify the CMS.
        return signatureBytes is null
            ? Record(ProvenanceResult.Unsigned)
            : Record(VerifyCms(signatureBytes));
    }

    // Reads the root-level .signature.p7s entry into memory, or null when the entry is absent.
    // Buffers the incoming stream to a MemoryStream first because ZipArchive needs to seek the
    // central directory; the buffer is capped so a hostile Content-Length cannot exhaust memory.
    private static async Task<byte[]?> ExtractSignatureEntryAsync(Stream nupkg, long maxBytes, CancellationToken ct)
    {
        long cap = Math.Min(maxBytes <= 0 ? long.MaxValue : maxBytes, int.MaxValue);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[81920];
        long total = 0;
        int read;
        while ((read = await nupkg.ReadAsync(chunk.AsMemory(0, chunk.Length), ct)) > 0)
        {
            total += read;
            if (total > cap)
            {
                throw new InvalidOperationException("NuGet package exceeds the verification size cap.");
            }

            buffer.Write(chunk, 0, read);
        }

        buffer.Position = 0;
        using var zip = new ZipArchive(buffer, ZipArchiveMode.Read);
        var entry = zip.GetEntry(SignatureEntryName);
        if (entry is null)
        {
            return null;
        }

        if (entry.Length > MaxSignatureBytes)
        {
            throw new InvalidOperationException("NuGet signature entry exceeds the size cap.");
        }

        using var entryStream = entry.Open();
        using var sigBuffer = new MemoryStream();
        await entryStream.CopyToAsync(sigBuffer, ct);
        return sigBuffer.ToArray();
    }

    // Decodes the CMS, validates the signature over its embedded content, then confirms a signer
    // chains to a pinned anchor. Returns Failed (never throws) on any decode/crypto failure.
    private ProvenanceResult VerifyCms(byte[] signatureBytes)
    {
        SignedCms cms;
        try
        {
            cms = new SignedCms();
            cms.Decode(signatureBytes);
        }
        catch (CryptographicException)
        {
            return ProvenanceResult.Failed;
        }

        try
        {
            // verifySignatureOnly: true validates the signature math over the embedded signed
            // content without performing .NET's own chain build (we pin the chain ourselves
            // below against the operator anchors, never the OS trust store).
            cms.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException)
        {
            // Signature does not validate over its content — tampered signature or wrong key.
            return ProvenanceResult.Failed;
        }

        // A signed package carries at least one signer; both the author signature and the
        // repository countersignature (NuGet nests the repository signature as a countersigner)
        // are candidates. Any signer that chains to a pinned anchor establishes trust.
        var anchors = _trust.GetAnchors();
        var trustedSigner = EnumerateSignerCertificates(cms)
            .FirstOrDefault(cert => ChainsToPinnedAnchor(cert, anchors));

        // A signature was present and valid, but no signer chained to a pinned anchor.
        return trustedSigner is not null
            ? ProvenanceResult.Verified(SignerIdentity(trustedSigner))
            : ProvenanceResult.Failed;
    }

    // Yields the signing certificate of every signer and nested countersigner (NuGet's repository
    // signature is a countersignature on the primary signer) so a pinned-anchor match on either is
    // honoured. Signers whose certificate is absent from the CMS are skipped.
    private static IEnumerable<X509Certificate2> EnumerateSignerCertificates(SignedCms cms)
    {
        foreach (var signer in cms.SignerInfos)
        {
            if (signer.Certificate is { } cert)
            {
                yield return cert;
            }

            foreach (var counter in signer.CounterSignerInfos)
            {
                if (counter.Certificate is { } counterCert)
                {
                    yield return counterCert;
                }
            }
        }
    }

    // Builds a chain that trusts ONLY the operator-pinned anchors (CustomRootTrust), so a
    // certificate that chains to a public CA but not to a pinned anchor is rejected. Revocation
    // is not checked: the trust decision is the pinned anchor, and an air-gapped or offline
    // deployment must not fail-open or hang on an unreachable OCSP/CRL endpoint.
    private static bool ChainsToPinnedAnchor(X509Certificate2 cert, X509Certificate2Collection anchors)
    {
        using var chain = new X509Chain
        {
            ChainPolicy =
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                // The pinned anchor may be a root or an intermediate; allow either to terminate
                // the chain. ExtraStore lets the chain builder find intermediates shipped in the
                // signature when the operator pinned only the root.
                VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                    | X509VerificationFlags.IgnoreCtlNotTimeValid,
            },
        };
        foreach (var anchor in anchors)
        {
            chain.ChainPolicy.CustomTrustStore.Add(anchor);
        }

        // Build returns true only when the chain terminates in a CustomTrustStore anchor with no
        // disqualifying status. IgnoreNotTimeValid keeps a pinned-but-expired anchor usable (the
        // operator's pin is the trust decision, not the cert's notAfter) without trusting OS roots.
        return chain.Build(cert);
    }

    // Human-readable signer identity for the persisted provenance_signer column: prefer the
    // certificate subject, fall back to the SHA-256 thumbprint when the subject is empty.
    private static string SignerIdentity(X509Certificate2 cert)
    {
        string subject = cert.Subject;
        return string.IsNullOrWhiteSpace(subject)
            ? cert.GetCertHashString(HashAlgorithmName.SHA256)
            : subject;
    }

    // Emits the OTel result counter (ecosystem + result only — no per-package labels, to stay
    // inside the cardinality budget). NotApplicable is never recorded here (it is returned only
    // by the metadata-shaped VerifyAsync, which the NuGet ingest path does not call).
    private static ProvenanceResult Record(ProvenanceResult result)
    {
        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", "nuget"),
            new KeyValuePair<string, object?>("result", ResultLabel(result.Status)));
        return result;
    }

    private static string ResultLabel(ProvenanceStatus status) => status switch
    {
        ProvenanceStatus.Verified => "verified",
        ProvenanceStatus.Failed => "failed",
        ProvenanceStatus.Unsigned => "unsigned",
        _ => "not_applicable",
    };
}
