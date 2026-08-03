// Identity of one file row inside a version group, for use as a keyed-each key.
//
// Sibling rows of a multi-file version share the version's `id` — a hosted NuGet `.nupkg` and its
// `.snupkg` are two files of ONE `package_versions` row, so the API reports the same `id` twice.
// Svelte throws `each_key_duplicate` on a duplicate key in BOTH dev and production builds, which
// would blank the whole detail panel.
//
// `filename` is the right key because it is what actually identifies a file: the schema declares
// it `NOT NULL` with `UNIQUE (package_version_id, filename)`, and it is the value the download
// endpoint addresses a file by (`?file=`). Proxy rows carry distinct `id`s already, so the
// fallback covers a row whose filename is absent without ever colliding.
export function fileRowKey(file) {
  return file.filename ?? file.id
}
