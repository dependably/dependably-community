import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import svelte from 'eslint-plugin-svelte'
import globals from 'globals'
import prettier from 'eslint-config-prettier'

// Emoji codepoints are banned in Svelte markup — the UI renders icons from the
// web/public/icons.svg sprite instead (DESIGN.md §12). This rule is the single
// enforcing gate: it runs via lint-staged pre-commit, `npm run lint`, and the CI
// frontend-lint job. The PostToolUse hook in .claude/hooks/ carries its own copy
// of this range as fast edit-time advice; that copy is not a gate.
//
// Ranges: 1F000-1FAFF (emoji + playing cards), 2300-23FF (⌚⏰⏳),
// 2600-27BF (☀✅✨), 2B00-2BFF (⬆⭐), FE0F (variation selector).
const EMOJI_RANGES = '[\\u{1F000}-\\u{1FAFF}\\u{2300}-\\u{23FF}\\u{2600}-\\u{27BF}\\u{2B00}-\\u{2BFF}\\u{FE0F}]'

const dependably = {
  rules: {
    'no-emoji': {
      meta: {
        type: 'problem',
        docs: { description: 'Disallow emoji codepoints; use the icons.svg sprite.' },
        schema: [],
        messages: {
          emoji: 'Emoji codepoint {{cp}} — use a sprite from web/public/icons.svg instead (DESIGN.md §12).',
        },
      },
      create(context) {
        return {
          Program() {
            const sourceCode = context.sourceCode
            const text = sourceCode.getText()
            const re = new RegExp(EMOJI_RANGES, 'gu')
            let match
            while ((match = re.exec(text)) !== null) {
              const cp = match[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
              context.report({
                loc: {
                  start: sourceCode.getLocFromIndex(match.index),
                  end: sourceCode.getLocFromIndex(match.index + match[0].length),
                },
                messageId: 'emoji',
                data: { cp: `U+${cp}` },
              })
            }
          },
        }
      },
    },
  },
}

export default [
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs['flat/recommended'],
  prettier,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
        // Injected by Vite `define` (vite.config.js).
        __APP_VERSION__: 'readonly',
      },
    },
  },
  {
    files: ['**/*.svelte'],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
      },
    },
    plugins: { dependably },
    rules: {
      'dependably/no-emoji': 'error',
    },
  },
  {
    rules: {
      // visually adjacent labels — same suppression as svelte.config.js
      'svelte/a11y-label-has-associated-control': 'off',
      'eqeqeq': ['error', 'always'],
      'no-console': ['warn', { allow: ['error', 'warn'] }],
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
  {
    ignores: ['dist/**', 'e2e/playwright-report/**', 'src/lib/vendor/**'],
  },
]
