# Log output

Dependably writes structured logs to stdout via Serilog. Every log event is emitted as one object on one line — suitable for direct ingestion by Elastic Stack, AWS CloudWatch Logs, Datadog, Grafana Loki, or any line-oriented log aggregator. The format is controlled by `LOG_FORMAT`.

## Format toggle

| `LOG_FORMAT` value | Description |
|---|---|
| `json` (default) | ECS (Elastic Common Schema) structured JSON, one object per line. Suitable for log-ingestion pipelines. |
| `text` | Human-readable Serilog console output. Suitable for interactive `docker logs` tailing. |

## ECS JSON schema

When `LOG_FORMAT=json` (the default), the `Elastic.CommonSchema.Serilog` package (`EcsTextFormatter`) formats each event as a JSON object conforming to the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html). Key fields:

| Field | Type | Always present | Description |
|---|---|---|---|
| `@timestamp` | string (ISO-8601) | yes | Event timestamp in the local timezone with offset, e.g. `2026-06-15T12:00:00.000+00:00`. |
| `log.level` | string | yes | Serilog level name: `Verbose`, `Debug`, `Information`, `Warning`, `Error`, or `Fatal`. Always emitted, including for `Information` events. |
| `message` | string | yes | Rendered log message with all template holes filled. |
| `ecs.version` | string | yes | ECS schema version, e.g. `9.0.0`. |
| `log.logger` | string (nested under `log`) | when set | Full type name of the logger, e.g. `Dependably.Infrastructure.StatsRefreshService`. |
| `trace.id` / `span.id` | string | when set | OTel trace and span IDs from the current `Activity`, if any. |
| *(additional)* | varies | varies | Remaining Serilog properties appear under a `labels` object. Sensitive values are already redacted to `[REDACTED]` by the upstream enricher before the formatter sees them. |

Example line (formatted for readability — actual output is one line):

```json
{
  "@timestamp": "2026-06-15T12:00:00.000+00:00",
  "log.level": "Information",
  "message": "Package pushed: my-pkg 1.0.0",
  "ecs.version": "9.0.0",
  "log": { "logger": "Dependably.Api.NuGetController" },
  "labels": { "OrgId": "default", "Ecosystem": "nuget", "PackageName": "my-pkg", "Version": "1.0.0" }
}
```

## Text format

When `LOG_FORMAT=text`, Serilog's built-in console output template is used:

```
[2026-06-15 12:00:00.000 INF] Dependably.Api.NuGetController: Package pushed: my-pkg 1.0.0
```

Exception stack traces appear on subsequent lines immediately after the primary line.

## Level vocabulary

| `log.level` value | Serilog level | Typical use |
|---|---|---|
| `Verbose` | Verbose | Fine-grained diagnostic events, disabled in production by default. |
| `Debug` | Debug | Periodic heartbeats and operational ticks (e.g. janitor start/done, stats refresh complete). |
| `Information` | Information | Normal operational events (pushes, proxy hits, first-boot). |
| `Warning` | Warning | Recoverable anomalies (upstream timeouts, checksum mismatches, schema-migration skips). |
| `Error` | Error | Failed requests and unhandled exceptions caught at the boundary. |
| `Fatal` | Fatal | Unrecoverable startup failures. |

## OTLP bridge

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, logs are also forwarded via the Serilog OTLP sink in addition to the always-on stdout JSON sink. Air-gap deployments leave this unset and consume stdout only.

## AWS CloudWatch path

1. Run the container with `awslogs` driver (or Firelens/FluentBit) pointed at a CloudWatch log group.
2. Set `LOG_FORMAT=json` (the default).
3. In CloudWatch Logs Insights, query ECS fields directly:

```
fields `@timestamp`, `log.level`, message, `log.logger`
| filter `log.level` = "Error"
| sort `@timestamp` desc
```

## No in-app log retrieval

There is no HTTP endpoint that serves log records. Logs are write-only from the application's perspective; retrieval and search are the responsibility of the log aggregator configured in the deployment environment.
