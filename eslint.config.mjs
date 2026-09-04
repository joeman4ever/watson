// Minimum lint for a verifier. Not a style project — these rules catch the
// classes of mistake that would make the engine wrong rather than untidy:
// unused bindings (a check that was written and never wired), undeclared
// globals, and unreachable code.
export default [
  {
    files: ['src/**/*.mjs', 'test/**/*.mjs', 'tools/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        process: 'readonly', console: 'readonly', URL: 'readonly', fetch: 'readonly',
        // `Response` is a global of the same fetch API as `fetch` above; tests use
        // it to stand a product response up without a server.
        Response: 'readonly', globalThis: 'readonly',
        AbortSignal: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly', Buffer: 'readonly',
        structuredClone: 'readonly',
        // Browser globals. These are NOT available to the engine — they appear only
        // inside `page.evaluate(() => ...)` callbacks, whose bodies are serialised and
        // run in Chromium. ESLint cannot see that boundary, so they are declared here
        // rather than disabled inline at each call site.
        document: 'readonly', window: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-undef': 'error',
      'no-unreachable': 'error',
      'no-constant-condition': ['error', { checkLoops: false }],
      'no-fallthrough': 'error',
      eqeqeq: ['error', 'smart'],
    },
  },
];
