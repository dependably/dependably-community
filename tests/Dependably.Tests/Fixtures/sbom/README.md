# SBOM / VEX / SARIF fixtures

Spec-valid documents for the project-plane upload, merge, triage and export paths. Component
purls and advisory ids are shared across the documents so all of them can be uploaded against one
project version and merge coherently; `cyclonedx-1.6-inventory.json` is the anchor document the
others cross-reference.

- `cyclonedx-1.6-inventory.json` — CycloneDX 1.6 inventory SBOM: 13 components across npm, PyPI
  and NuGet purls (including a scoped `@babel/core` and digit-bearing names), a `dependencies[]`
  adjacency graph with direct and transitive edges, licenses in both `expression` and `license.id`
  form plus one component with none, and `scope` values covering `required`, `optional`,
  `excluded` and absent.
- `cyclonedx-1.5-minimal.json` — small valid CycloneDX 1.5 SBOM; exercises the middle of the
  accepted 1.4–1.6 spec-version range.
- `cyclonedx-1.4-minimal.json` — small valid CycloneDX 1.4 SBOM (array-form `metadata.tools`);
  exercises the lower bound of the accepted range.
- `cyclonedx-1.3-unsupported.json` — CycloneDX 1.3 document; upload rejects it as an unsupported
  spec version (422).
- `cyclonedx-1.6-vdr.json` — the same inventory plus an embedded `vulnerabilities[]` array with
  `analysis` blocks; exercises the SBOM-with-embedded-VEX-statements path.
- `cyclonedx-1.6-vex.json` — vulnerabilities-only CycloneDX VEX covering the full analysis-state
  vocabulary (`in_triage`, `exploitable`, `resolved`, `resolved_with_pedigree`, `false_positive`,
  `not_affected`), including one statement whose product (`pkg:npm/event-stream@3.3.6`) matches no
  inventory component.
- `openvex-1.0.json` — OpenVEX document covering all four OpenVEX statuses (`not_affected`,
  `affected`, `fixed`, `under_investigation`) with justification/action statements; exercises the
  OpenVEX→CycloneDX vocabulary mapping.
- `sarif-2.1.0-sbom-reach.json` — SARIF 2.1.0 as the sbom-reach producer emits it: per-result
  `reachability`/`confidence`/`purl`/`dependencyKind`/`dependencyPath`/`security-severity`
  property bags, the `dependencyScope` (`dev`/`runtime`/`unknown`) and `sbomScope`
  (`required`/`optional`/`excluded`) split, `runtimePresent`/`diagnostics`/`recommendation`
  extras, `partialFingerprints['sbomReach/v1']` on every result, `suppressions[]` on one result,
  and one result whose purl matches no inventory component.
- `sarif-2.1.0-generic.json` — SARIF 2.1.0 from an unrelated producer carrying none of the
  sbom-reach property bags; exercises the tolerated-defensively path.
