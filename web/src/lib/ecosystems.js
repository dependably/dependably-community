// Single source of truth for the ecosystem vocabulary. Internal key === backend ID;
// label is the user-facing display string (OCI renders as "Docker" — only place the
// key/label distinction matters). Add a new ecosystem here, then add matching CSS
// variables in app.css and a snippet generator in OrgController.GetSetup.
export const ECOSYSTEMS = ['pypi', 'npm', 'nuget', 'maven', 'rpm', 'oci', 'golang', 'cargo']

export const ECO_LABEL = {
  pypi:   'PyPI',
  npm:    'npm',
  nuget:  'NuGet',
  maven:  'Maven',
  rpm:    'RPM',
  oci:    'Docker',
  golang: 'Go',
  cargo:  'Cargo',
}
