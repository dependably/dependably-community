namespace Dependably.Infrastructure;

/// <summary>
/// Anchor type for reflection against the Dependably.Core assembly. Core startup wiring reads the
/// informational/assembly version from <c>typeof(CoreAssemblyMarker).Assembly</c> rather than
/// <c>typeof(Program)</c>: <c>Program</c> lives in the composition-root assembly, which Core does
/// not (and must not) reference. All host assemblies (full root, edge root, Core) carry the same
/// shared <c>Directory.Build.props</c> version, so the value is identical wherever it is read.
/// </summary>
internal static class CoreAssemblyMarker
{
}
