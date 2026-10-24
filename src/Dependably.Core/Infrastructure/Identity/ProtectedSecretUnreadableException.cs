namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Thrown when a stored secret that a caller needs cannot be decrypted. It names the record —
/// kind, table, row id and owning org — and the reason, using the same identifiers
/// <see cref="ProtectedSecretVerifier"/> reports, so the log line a failing feature writes points
/// at the row an operator has to repair. It never carries the stored value or its ciphertext.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization (SerializationInfo/StreamingContext) is obsolete in .NET 8+ and disabled by default; this exception is never serialized across processes.")]
public sealed class ProtectedSecretUnreadableException : Exception
{
    internal ProtectedSecretUnreadableException(ProtectedSecretRow row, string reason)
        : base(
            $"Stored secret {row.Kind} in {row.Table} row {row.RowId} (org {row.OrgId ?? "none"}) "
            + $"does not decrypt: {reason}.")
    {
        Kind = row.Kind;
        Table = row.Table;
        RowId = row.RowId;
        OrgId = row.OrgId;
        Reason = reason;
    }

    /// <summary>One of <see cref="ProtectedSecretKinds"/>, or an instance-secret key name.</summary>
    public string Kind { get; }

    /// <summary>The table holding the value.</summary>
    public string Table { get; }

    /// <summary>The row's primary key.</summary>
    public string RowId { get; }

    /// <summary>The owning org, or null for an instance-level secret.</summary>
    public string? OrgId { get; }

    /// <summary>One of <see cref="ProtectedSecretFailureReasons"/>.</summary>
    public string Reason { get; }
}

/// <summary>
/// Identifies one stored secret for logs and errors, without its value.
/// </summary>
/// <param name="Kind">One of <see cref="ProtectedSecretKinds"/>, or an instance-secret key name.</param>
/// <param name="Table">The table holding the value.</param>
/// <param name="RowId">The row's primary key.</param>
/// <param name="OrgId">The owning org, or null for an instance-level secret.</param>
public sealed record ProtectedSecretRow(string Kind, string Table, string RowId, string? OrgId);
