namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Serializes every test class that touches the process-wide <c>DependablyMeter.Meter</c> in a
/// way that races other tests: classes that attach a <see cref="System.Diagnostics.Metrics.MeterListener"/>
/// filtered only by meter name + instrument name and assert exact counts, and classes that
/// drive real production code emitting to those same instruments. <c>DependablyMeter.Meter</c>
/// is a deliberately static, process-wide taxonomy (see
/// <c>Dependably.Core/Infrastructure/Observability/DependablyMeter.cs</c>) — migrating it to
/// <c>IMeterFactory</c> just to satisfy tests would be the tail wagging the dog, so isolation
/// lives on the test side instead: every member of this collection runs alone, never
/// concurrently with any other collection, while the rest of the suite stays parallel.
///
/// Membership is enforced by <c>MeterListenerIsolationComplianceTests</c> — any new
/// <c>MeterListener</c> filtered by <c>DependablyMeter.MeterName</c> must live in a class
/// carrying <c>[Collection("MeterSensitive")]</c>.
/// </summary>
[CollectionDefinition("MeterSensitive", DisableParallelization = true)]
public sealed class MeterSensitiveCollection;
