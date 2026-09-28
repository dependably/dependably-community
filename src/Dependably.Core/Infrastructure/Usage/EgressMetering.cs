using Microsoft.AspNetCore.Http;

namespace Dependably.Infrastructure.Usage;

/// <summary>What a metered response carries, and so which meter its bytes count toward.</summary>
public enum EgressKind
{
    /// <summary>An artifact body: a tarball, wheel, jar, package, or layer.</summary>
    Artifact,

    /// <summary>Package metadata: a packument, index, registration page, manifest, or tag list.</summary>
    Metadata,

    /// <summary>
    /// The action serves both, depending on the path it resolves (the catch-all routes). The
    /// handler names the kind with <see cref="EgressMeteringHttpContextExtensions.ClassifyEgress"/>
    /// before it returns; a response it never classifies is recorded as metadata and counted on
    /// <c>dependably.usage_events.unclassified</c>, so a missed call site is visible rather than
    /// silently billed as an artifact.
    /// </summary>
    PerResponse,
}

/// <summary>
/// Marks a protocol action whose response bodies are metered as egress. The action's
/// <see cref="Ecosystem"/> becomes the event's <c>source</c>. Every routed GET on a protocol
/// controller carries this attribute or an explicit <c>// egress-ok: &lt;reason&gt;</c> opt-out
/// (<c>MeteredEgressComplianceTests</c>).
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
public sealed class MeteredEgressAttribute : Attribute
{
    public MeteredEgressAttribute(EgressKind kind, string ecosystem)
    {
        Kind = kind;
        Ecosystem = ecosystem;
    }

    public EgressKind Kind { get; }

    public string Ecosystem { get; }
}

/// <summary>
/// Per-request metering state, installed by <see cref="EgressMeteringMiddleware"/> on a metered
/// endpoint. Handlers reach it through <see cref="EgressMeteringHttpContextExtensions"/>; on an
/// unmetered endpoint it is absent and those extensions do nothing.
/// </summary>
public sealed class EgressMeteringFeature
{
    internal EgressMeteringFeature(EgressKind kind) => Kind = kind;

    /// <summary>The response's kind. Starts as the attribute's, and a handler may narrow it.</summary>
    public EgressKind Kind { get; internal set; }

    /// <summary>Set when the response hands the client a redirect to the object's bytes.</summary>
    public RedirectedEgress? Redirect { get; internal set; }
}

/// <summary>An artifact served by redirect: the object's size and a reference to it.</summary>
public sealed record RedirectedEgress(long Bytes, string ObjectRef);

public static class EgressMeteringHttpContextExtensions
{
    /// <summary>
    /// Names what this response carries, for an action declared <see cref="EgressKind.PerResponse"/>.
    /// Also valid on a fixed-kind action that needs to override it for one path. No effect on an
    /// unmetered endpoint.
    /// </summary>
    public static void ClassifyEgress(this HttpContext context, EgressKind kind)
    {
        if (kind == EgressKind.PerResponse)
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "A response is classified as Artifact or Metadata.");
        }

        if (context.Features.Get<EgressMeteringFeature>() is { } feature)
        {
            feature.Kind = kind;
        }
    }

    /// <summary>
    /// Records that this response redirects the client to an artifact's bytes instead of streaming
    /// them. The redirect writes almost no body, so without this the delivery path that carries
    /// the most bytes would be metered as nothing. Call it only once the redirect is certain: after
    /// every authorization, tenancy, and gate check has passed and the URL has been signed.
    /// </summary>
    public static void RecordRedirectedEgress(this HttpContext context, long bytes, string objectRef)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        if (context.Features.Get<EgressMeteringFeature>() is { } feature)
        {
            feature.Kind = EgressKind.Artifact;
            feature.Redirect = new RedirectedEgress(bytes, objectRef);
        }
    }
}
