namespace Dependably.Security;

/// <summary>
/// Operator opt-ins for the two places a cryptographically broken digest still carries weight
/// in a security decision. Both default to <b>off</b>: a weak algorithm is never accepted
/// because it happens to be what an upstream sent, only because an operator asked for it.
///
/// <list type="bullet">
///   <item><b><c>Npm:AcceptSha1Shasum</c></b> — whether a packument that carries only
///   <c>dist.shasum</c> (hex SHA-1, no <c>dist.integrity</c> SRI) counts as an integrity
///   verification for proxy cache admission. Off, the SHA-1 is treated as <i>unverified</i>:
///   the artefact is admitted on the same footing as any ecosystem whose metadata carries no
///   digest at all, and the registry makes no integrity claim it cannot back.</item>
///   <item><b><c>Apk:AcceptSha1IndexSignatures</c></b> — whether a
///   <c>.SIGN.RSA.&lt;keyname&gt;</c> (SHA-1) entry in an <c>APKINDEX.tar.gz</c> may satisfy
///   index signature verification. Off, only <c>.SIGN.RSA256.*</c> / <c>.SIGN.RSA512.*</c>
///   entries can verify, and an index carrying nothing else fails closed.</item>
/// </list>
///
/// Each acceptance — and each refusal — logs once per process. Both sit on hot paths that
/// repeat per request, so an unconditional log would be a per-fetch line; one warning is
/// enough to tell an operator which posture is in force and why an artefact behaved the way
/// it did.
/// </summary>
public sealed class WeakAlgorithmAcceptance
{
    /// <summary>Configuration key for the npm SHA-1 <c>shasum</c> opt-in.</summary>
    public const string NpmSha1ShasumKey = "Npm:AcceptSha1Shasum";

    /// <summary>Configuration key for the apk SHA-1 index-signature opt-in.</summary>
    public const string ApkSha1IndexSignatureKey = "Apk:AcceptSha1IndexSignatures";

    private readonly ILogger _logger;
    private int _npmAcceptedLogged;
    private int _npmSkippedLogged;
    private int _apkAcceptedLogged;
    private int _apkRefusedLogged;

    /// <summary>DI constructor — reads both opt-ins from configuration, defaulting to off.</summary>
    public WeakAlgorithmAcceptance(IConfiguration configuration, ILogger<WeakAlgorithmAcceptance> logger)
        : this(
            configuration.GetValue(NpmSha1ShasumKey, false),
            configuration.GetValue(ApkSha1IndexSignatureKey, false),
            logger)
    {
    }

    /// <summary>Explicit constructor used by tests and by <see cref="RefuseAll"/>.</summary>
    public WeakAlgorithmAcceptance(bool npmSha1Shasum, bool apkSha1IndexSignatures, ILogger logger)
    {
        NpmSha1Shasum = npmSha1Shasum;
        ApkSha1IndexSignatures = apkSha1IndexSignatures;
        _logger = logger;
    }

    /// <summary>
    /// The default posture — every weak-algorithm opt-in off. Used where an instance is
    /// constructed without configuration (a call site that has not been handed the DI
    /// singleton), so the fallback is the safe one rather than the permissive one.
    /// </summary>
    public static WeakAlgorithmAcceptance RefuseAll { get; } =
        new(false, false, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

    /// <summary>True when a SHA-1-only npm <c>dist.shasum</c> counts as a verified checksum.</summary>
    public bool NpmSha1Shasum { get; }

    /// <summary>True when a SHA-1 <c>.SIGN.RSA.*</c> apk index signature may verify.</summary>
    public bool ApkSha1IndexSignatures { get; }

    /// <summary>Records that a SHA-1 npm <c>shasum</c> was used as the verification basis.</summary>
    public void NoteNpmSha1Accepted()
    {
        if (Interlocked.Exchange(ref _npmAcceptedLogged, 1) != 0)
        {
            return;
        }

        _logger.LogWarning(
            "Accepting a SHA-1 npm dist.shasum as the integrity check for proxy cache admission "
            + "because {Key}=true. SHA-1 is chosen-prefix-collision-broken, so this is not an "
            + "integrity guarantee against an adversary; unset the key to treat a shasum-only "
            + "packument as unverified instead.",
            NpmSha1ShasumKey);
    }

    /// <summary>
    /// Records that a SHA-1-only npm <c>shasum</c> was skipped rather than treated as a
    /// verification. The artefact still serves — it is admitted unverified, exactly as an
    /// artefact whose upstream metadata carries no digest at all.
    /// </summary>
    public void NoteNpmSha1Skipped()
    {
        if (Interlocked.Exchange(ref _npmSkippedLogged, 1) != 0)
        {
            return;
        }

        _logger.LogWarning(
            "An npm packument carried only a SHA-1 dist.shasum and no sha512 SRI, so the "
            + "artefact is admitted to the proxy cache unverified rather than counted as "
            + "checksum-verified. Set {Key}=true to accept the SHA-1 as a verification.",
            NpmSha1ShasumKey);
    }

    /// <summary>Records that a SHA-1 apk index signature satisfied verification.</summary>
    public void NoteApkSha1Accepted()
    {
        if (Interlocked.Exchange(ref _apkAcceptedLogged, 1) != 0)
        {
            return;
        }

        _logger.LogWarning(
            "Accepting a SHA-1 (.SIGN.RSA.*) APKINDEX.tar.gz signature because {Key}=true. The "
            + "digest algorithm is named by the index being verified, so an attacker who can "
            + "produce a chosen-prefix SHA-1 collision chooses the weak arm; unset the key to "
            + "require .SIGN.RSA256/.SIGN.RSA512.",
            ApkSha1IndexSignatureKey);
    }

    /// <summary>
    /// Records that a SHA-1 apk index signature was refused. Refusal is a verification
    /// failure, not a pass — the caller treats the index as untrusted.
    /// </summary>
    public void NoteApkSha1Refused()
    {
        if (Interlocked.Exchange(ref _apkRefusedLogged, 1) != 0)
        {
            return;
        }

        _logger.LogWarning(
            "Refusing a SHA-1 (.SIGN.RSA.*) APKINDEX.tar.gz signature: the digest algorithm is "
            + "chosen by the index under verification and SHA-1 is collision-broken. Publish or "
            + "mirror an index signed with .SIGN.RSA256/.SIGN.RSA512, or set {Key}=true to accept "
            + "SHA-1 index signatures.",
            ApkSha1IndexSignatureKey);
    }
}
