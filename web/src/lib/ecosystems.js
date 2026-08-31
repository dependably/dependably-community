// Single source of truth for the ecosystem vocabulary. Internal key === backend ID;
// label is the user-facing display string (OCI renders as "Docker" — only place the
// key/label distinction matters). Add a new ecosystem here, then add matching CSS
// variables in app.css, a setup snippet generator in OrgController.GetSetup (the
// client CONFIGURATION document) and a builder in lib/installCommand.js (the
// per-artefact INVOCATION). installCommand.test.js pins its builder map against this
// list, so a missing builder fails the suite rather than silently rendering nothing.
export const ECOSYSTEMS = ['pypi', 'npm', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo', 'apk', 'terraform']

export const ECO_LABEL = {
  pypi:   'PyPI',
  npm:    'npm',
  nuget:  'NuGet',
  maven:  'Maven',
  rpm:    'RPM',
  oci:    'Docker',
  golang: 'Go',
  cargo:  'Cargo',
  apk:    'Alpine apk',
  terraform: 'Terraform',
}
