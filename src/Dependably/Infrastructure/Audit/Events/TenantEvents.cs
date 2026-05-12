using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

/// <summary>
/// Typed payloads for tenant settings + token lifecycle events (#52). Token events carry
/// the token id but never the raw secret — that's emitted exactly once in the API response
/// and never stored in plaintext.
/// </summary>
public static class TenantEvents
{
    public const string TypeSettingChange = "tenant.setting.change";
    public const string TypeTokenCreate = "tenant.token.create";
    public const string TypeTokenRevoke = "tenant.token.revoke";

    public sealed record SettingChange(string Key, object? PriorValue, object? NewValue)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record TokenCreate(
        string TokenId,
        string CapabilitiesJson,             // canonical JSON, byte-equal to the DB row
        IReadOnlyList<string> Capabilities,  // structured array for SIEM/JSON-path queries
        string TokenKind,                    // "user" | "cicd"
        DateTimeOffset? ExpiresAt)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record TokenRevoke(string TokenId, string TokenKind)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }
}
