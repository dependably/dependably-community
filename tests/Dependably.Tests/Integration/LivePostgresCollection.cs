namespace Dependably.Tests.Integration;

/// <summary>
/// xUnit collection marker that serialises all live-Postgres test classes against each other.
/// Tests in this collection share the same single Postgres <c>public</c> schema and each
/// perform a full <c>DROP SCHEMA public CASCADE; CREATE SCHEMA public;</c> reset at the start
/// of every test, so they must not run concurrently. xUnit runs test classes within the same
/// collection sequentially.
///
/// <c>DisableParallelization = true</c> additionally keeps this collection from running
/// concurrently with any OTHER collection — in particular
/// <c>Integration.ActivityWriterPostgresTests</c> (a member here) deliberately overflows the
/// activity-writer channel and increments the same process-wide
/// <c>dependably.activity_writer.dropped</c> counter that <c>Unit.ActivityWriterTests</c>
/// (in the <c>MeterSensitive</c> collection) asserts an exact count against. A test class can
/// carry only one <c>[Collection]</c>, so mutual exclusion between the two collections —
/// rather than merging membership — is how that cross-talk is closed.
/// </summary>
[CollectionDefinition("LivePostgres", DisableParallelization = true)]
public sealed class LivePostgresCollection;
