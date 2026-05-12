# SQLite-vs-Postgres gap log

Repo tests under `Category=Unit` run against in-memory SQLite via
[InMemoryDbFixture](Infrastructure/InMemoryDbFixture.cs). SQLite differs from
Postgres in weak typing, NULL ordering, JSON operators, case sensitivity,
and the join planner. Any query that relies on one of those behaviors needs
a Postgres-backed follow-up test (Testcontainers.PostgreSql) so SQLite
coverage doesn't mask real-prod regressions.

## How to append an entry

Each entry uses this schema. Free-form notes rot; the structure is mandatory:

```
### <Repo or service>.<MethodName>
- Query: <one-line summary, e.g. "uses lower() + 3-table JOIN">
- SQLite gap: <which SQLite behavior differs from Postgres>
- Follow-up: <what the Postgres test must assert>
- Added: <YYYY-MM-DD> / phase <N>
```

Add entries when a new repo test exercises any of:

- JSON (`json_extract`, `->>`, `jsonb_set`, etc.)
- Joins across 3+ tables
- Date arithmetic beyond simple ISO string comparison
- Collation-dependent comparison (`COLLATE NOCASE`, ICU collations)
- Aggregate `OVER (PARTITION BY ...)` window functions
- Recursive CTEs

The Testcontainers.PostgreSql follow-up pass works off this list. Until
that pass lands, this file is the inventory of known coverage gaps.

## Entries

### OrgRepository.SetUserAccountStatusAsync / LookupUsersAsync / IssuePasswordResetAsync
- Query: `WHERE lower(u.email) = lower(@email)` on a (tenant_id, email) UNIQUE index
- SQLite gap: SQLite's `lower()` is ASCII-only; Postgres `lower()` is locale-aware (ICU on modern installs). A user with non-ASCII email may mismatch between the two.
- Follow-up: Postgres test that inserts a non-ASCII email and confirms `SetUserAccountStatusAsync` resolves it case-insensitively.
- Added: 2026-05-11 / phase 2

### VulnerabilityRepository.GetVulnReportAsync / GetVulnSummaryAsync
- Query: 4-table JOIN (`package_version_vulns × package_versions × packages × orgs/vulnerabilities`)
- SQLite gap: SQLite's planner has no statistics-based reordering. Postgres may pick a different join order under load; correctness should be identical but performance is not.
- Follow-up: Postgres-backed test with 10k rows asserting `GetVulnReportAsync` returns the same set + ordering at scale.
- Added: 2026-05-11 / phase 2

### PackageRepository.GetOrgStatsAsync
- Query: aggregates with `strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-7 days'))` and similar
- SQLite gap: Postgres uses `NOW() - INTERVAL '7 days'`; the SchemaInitializer rewrites the SQL but the date-arithmetic semantics differ subtly (Postgres respects timezone-aware comparisons natively).
- Follow-up: Postgres test that inserts activity rows at 6/7/8 day boundaries and asserts the bucket boundaries match SQLite's behaviour.
- Added: 2026-05-11 / phase 2

### PackageRepository.ListPaginatedAsync
- Query: `WHERE p.name LIKE @searchPattern ESCAPE '\\'` with caller-escaped `%` and `_`
- SQLite gap: SQLite's `LIKE` is case-insensitive by default for ASCII; Postgres `LIKE` is case-sensitive (callers must opt into `ILIKE` for case-insensitive matching).
- Follow-up: Postgres test confirming search matches behave consistently (or alternatively that the Postgres schema variant uses `ILIKE`).
- Added: 2026-05-11 / phase 2

### SamlConfigRepository.TryConsumeTestRunAsync
- Query: `WHERE expires_at > @now` over ISO 8601 strings
- SQLite gap: SQLite compares TEXT lexicographically; works for `yyyy-MM-ddTHH:mm:ssZ` but breaks if any caller writes a different format. Postgres uses `TIMESTAMPTZ` natively.
- Follow-up: Postgres test that exercises the consume path across DST + leap-second boundaries.
- Added: 2026-05-11 / phase 2
