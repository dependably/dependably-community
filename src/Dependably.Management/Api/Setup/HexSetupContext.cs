namespace Dependably.Api.Setup;

/// <summary>The tenant facts a Hex setup recipe embeds: the org's registry signing public key (PEM).</summary>
public sealed record HexSetupContext(string? PublicKeyPem);
