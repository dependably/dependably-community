import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../src/Dependably/wwwroot',
    emptyOutDir: true,
    // esbuild avoids lightningcss's per-platform native binary, whose
    // optional-dep install is unreliable under `npm ci` in cross-platform
    // Docker builds (e.g. linux-arm64-musl missing from a macOS lockfile).
    cssMinify: 'esbuild',
  },
})
