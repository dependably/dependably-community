// The SharedResource marker lives in the Dependably namespace while its .resx ships in the
// Dependably.Core assembly. Declaring the localization root namespace as Dependably lets the
// resource-manager localizer factory derive the base name (Dependably.Resources.SharedResource)
// from the marker's namespace rather than the assembly name, matching the embedded resource's
// pinned LogicalName in the csproj.
[assembly: Microsoft.Extensions.Localization.RootNamespace("Dependably")]

namespace Dependably;

/// <summary>Marker class for IStringLocalizer&lt;SharedResource&gt; injection.</summary>
public class SharedResource { }
