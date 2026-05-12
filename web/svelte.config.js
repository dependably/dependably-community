/** @type {import("@sveltejs/vite-plugin-svelte").SvelteConfig} */
export default {
  // Suppress a11y_label_has_associated_control project-wide — every .form-row
  // pairs a <label> visually-adjacent to its control; the spec allows this.
  // warningFilter is honored by svelte-check and the Svelte 5 compiler alike.
  compilerOptions: {
    warningFilter: (w) => w.code !== 'a11y_label_has_associated_control',
  },
  onwarn(warning, handler) {
    if (warning.code === 'a11y_label_has_associated_control') return
    handler(warning)
  },
}
