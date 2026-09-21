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
  accepted 1.4–1.7 spec-version range.
- `cyclonedx-1.4-minimal.json` — small valid CycloneDX 1.4 SBOM (array-form `metadata.tools`);
  exercises the lower bound of the accepted range.
- `cyclonedx-1.7-minimal.json` — small valid CycloneDX 1.7 SBOM at the upper bound of the
  accepted range, carrying the constructs only 1.7 admits: a component declaring `versionRange`
  and no `version`, one declaring `isExternal`, a `licenses` array mixing a `license.id` entry
  with an `expression` entry (1.6 allowed only one form per array), and a `Streebog-256` hash
  from the algorithm set 1.7 widened.
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
- `spdx-2.3-npm-syft.json` — a real SPDX 2.3 JSON document, verbatim output of `syft dir:.`
  (Anchore Syft 1.46.0, the same tool the ecosystem defaults to for SPDX generation) against a
  small real npm project (a `package.json`/`package-lock.json` declaring `lodash` and `chalk`).
  Extracted as-is and not modified after extraction — not hand-written to match this parser's
  assumptions. Exercises real-producer shapes a hand-written document would not: `NOASSERTION`
  on every `supplier` and on most `licenseConcluded`/`licenseDeclared` pairs, a `downloadLocation`
  usable as a distribution URL for two of the three packages, `DEPENDENCY_OF` relationships (the
  inverse of `DEPENDS_ON`), and — the one this parser's own doc comment calls out — a `DESCRIBES`
  relationship naming the *scanned directory* rather than the npm package the dependency edges are
  actually rooted at, so every component correctly reads `dependency_kind = 'graph-unknown'`
  rather than a fabricated direct/transitive split. Real package-level `checksums[]` were not
  observed from any generator tried (Syft, Trivy) across npm, PyPI and OS-package (APK) targets in
  the versions used here — only file-level checksums, a different SPDX element — so the
  ingest-side shape (verbatim SPDX algorithm spelling) is pinned by `SpdxParserTests`, and the
  export-side algorithm-spelling translation onto CycloneDX's `hash-alg` enum
  (`SbomExportService.AssertedAlgAliases`) is pinned separately by
  `SbomExportSchemaValidationTests`, against hand-constructed checksum values rather than this
  fixture.
- `spdx-2.2-unsupported.json` — hand-written SPDX 2.2 document; upload rejects it as an
  unsupported spdxVersion (422), the same role `cyclonedx-1.3-unsupported.json` plays for
  CycloneDX.
- `spdx-2.3-equivalence.json` / `cyclonedx-1.6-equivalence.json` — a matched pair describing the
  same project (`demo-app` depending directly on `left-pad`, with a producer, an author, an SPDX
  licence expression, a description, a copyright line, a website and distribution URL, and a
  checksum) in each format, deliberately hand-written rather than drawn from a real document: the
  discrimination test that consumes them (`SpdxAndCycloneDxDocumentsOfTheSameProject_ProduceTheSameComponentRow`
  in `Integration/SpdxIngestTests.cs`) needs full control over both documents' field values to
  assert the resulting `sbom_components` rows are identical, which two independent real-world
  documents cannot guarantee. The SPDX side's `supplier` carries a parenthetical email suffix
  (`Organization: Example Org (ops@example.com)`) the CycloneDX side's `publisher` does not, so the
  pair also exercises that the suffix is stripped rather than landing in `component_producer`. The
  two documents' checksums are deliberately spelled in each format's own vocabulary (`SHA-256` vs
  `SHA256`) — the discrimination test compares them algorithm-name-normalized rather than as raw
  strings, since the verbatim ingest spelling legitimately differs by design.
