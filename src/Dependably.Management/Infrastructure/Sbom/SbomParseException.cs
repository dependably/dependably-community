namespace Dependably.Infrastructure.Sbom;

/// <summary>Why a document was refused, so the controller can pick the localized message.</summary>
public enum SbomParseFailure
{
    /// <summary>The bytes are not well-formed JSON, or a required element is missing.</summary>
    Malformed,

    /// <summary>Well-formed JSON that is not the document kind the endpoint accepts.</summary>
    WrongDocumentKind,

    /// <summary>A CycloneDX specVersion outside the accepted range, or a SARIF version other than 2.1.0.</summary>
    UnsupportedSpecVersion,

    /// <summary>More components than one upload is allowed to carry.</summary>
    TooManyComponents,

    /// <summary>More analysis statements than one upload is allowed to carry.</summary>
    TooManyStatements,

    /// <summary>More SARIF results than one upload is allowed to carry.</summary>
    TooManyResults,
}

/// <summary>
/// Raised by the document parsers for every refusal a caller can act on. Carries a machine
/// reason rather than a message so the controller owns the localized text — a parser that
/// formatted English would put an unlocalizable string on a management-plane problem detail.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class SbomParseException : Exception
{
    public SbomParseException(SbomParseFailure failure, string? diagnostic = null)
        : base($"Document rejected: {failure}.")
    {
        Failure = failure;
        Diagnostic = diagnostic;
    }

    public SbomParseFailure Failure { get; }

    /// <summary>
    /// The offending value (a spec version, an entry ceiling) when naming it helps the caller
    /// fix the document. Never free-form prose — the localized message supplies that.
    /// </summary>
    public string? Diagnostic { get; }
}
