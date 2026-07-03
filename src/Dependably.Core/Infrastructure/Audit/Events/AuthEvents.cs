using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

/// <summary>
/// Typed payloads for authentication events. Email is intentionally never recorded
/// in plaintext — login.failure carries an email_hash. Login realm is <c>tenant</c> (regular
/// user) or <c>system</c> (operator dashboard).
/// </summary>
public static class AuthEvents
{
    public const string TypeLoginSuccess = "auth.login.success";
    public const string TypeLoginFailure = "auth.login.failure";
    public const string TypeLockout = "auth.lockout.triggered";

    public sealed record LoginSuccess(string Realm, string Method)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record LoginFailure(string Realm, string EmailHash)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Lockout(string Realm, string EmailHash)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public const string TypeSamlSuccess = "auth.saml.login.success";
    public const string TypeSamlFailure = "auth.saml.login.failure";

    public sealed record SamlSuccess(string IdpEntityId, string NameId, string Path)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record SamlFailure(string Reason, string? IdpEntityId, string? NameId)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }
}
