import { defineConfig } from 'vitest/config'

// No Svelte plugin: the unit-test harness covers pure-JS modules in src/lib.
// Component-level tests would re-add `@sveltejs/vite-plugin-svelte` here, but
// they're better served by the existing Playwright e2e suite.
export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.{test,spec}.{js,ts}'],
    globals: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['src/lib/**/*.js'],
      exclude: ['src/lib/**/*.test.js'],
    },
  },
})
