namespace Dependably.Protocol.Hex;

/// <summary>
/// A Hex registry resource, tarball or API body that cannot be read as the protocol defines it:
/// a malformed or oversized protobuf, a missing required field, a signature that does not
/// verify, or a payload whose embedded repository name is not the one expected. The message
/// names the failure without echoing untrusted bytes.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class HexProtocolException : Exception
{
    public HexProtocolException(string message) : base(message) { }
    public HexProtocolException(string message, Exception inner) : base(message, inner) { }
}
