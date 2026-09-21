# CycloneDX JSON schemas (validation fixtures)

The official CycloneDX 1.6 and 1.7 JSON schemas, plus the three schemas they `$ref` externally
(`cryptography-defs.schema.json`, `jsf-0.82.schema.json`, `spdx.schema.json`) — needed so a schema
validator can resolve the graph even though none of dependably's own exported documents populate
the branches those three cover (no cryptographic properties, no JSF signatures; licences use
`licenses[].expression`/`licenses[].license.id`, which the bom schema itself constrains without
delegating to `spdx.schema.json` for a bare SPDX-id string).

Extracted verbatim from the `CycloneDX.Core.dll` embedded resources shipped in the `CycloneDX`
NuGet package (the same OWASP CycloneDX .NET library `.gitlab-ci.yml`'s `cyclonedx` job already
uses to generate this project's own release SBOM), version 6.2.0 — not hand-written, not
downloaded from the network at test time, and not modified after extraction. That package ships
as a `DotnetTool` (no compile-time `lib/` assets), so its schemas are copied here as fixtures
rather than referenced live; `SbomExportSchemaValidationTests` validates against them with
`NJsonSchema`.

Bump the extracted files (and re-verify no `$ref` target changed) when the `CycloneDX` package
pin in `.gitlab-ci.yml` moves to a release that ships a newer bom-1.6/1.7 schema revision.
