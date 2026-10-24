namespace Dependably.Infrastructure;

/// <summary>
/// A one-shot credential (invite, password-reset link, email-change link) that was consumed,
/// together with the result of the write it authorized, which committed in the same transaction.
/// </summary>
public sealed record CredentialRedemption<TCredential, TResult>(TCredential Credential, TResult Result);
