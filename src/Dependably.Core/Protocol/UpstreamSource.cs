namespace Dependably.Protocol;

/// <summary>
/// A resolved upstream registry: its base URL plus a pre-built <c>Authorization</c> header value
/// (null for anonymous). The header is built once at resolve time — decrypting the stored secret
/// and selecting the scheme — so <see cref="UpstreamClient"/> stays ecosystem- and
/// auth-scheme-agnostic and never touches secret material or the protector.
///
/// The header is deliberately NOT part of any single-flight dedup or cache key: caches are
/// content-addressed and the <c>UNIQUE(org_id, ecosystem, url)</c> constraint guarantees one auth
/// per URL, so keying dedup on URL alone stays correct.
/// </summary>
public sealed record UpstreamSource(string Url, string? AuthorizationHeader);
