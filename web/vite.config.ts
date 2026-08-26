/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/* Vite is the bundler because the shell is a static SPA served by the Rust
 * gateway: there is no server runtime to justify Next.js, its Rollup build
 * gives the deterministic named chunks `check:bundle-size` measures against
 * `docs/09 §2`'s 250 KB budget, and Vitest reuses this exact transform
 * pipeline so tests and the shipped bundle cannot diverge. */
/* The development host, and why it is not `localhost`.
 *
 * `CLAUDE.md` rule 3: the tenant is never taken from a body field, a query
 * parameter or a header the client chose. In this deployment it comes from
 * custom-domain routing — the API reads the first label of the `Host` it was
 * reached on, so `tenant-alpha.localhost` *is* the tenant claim, and a request
 * to plain `localhost` has no tenant and is refused before it reaches a
 * handler.
 *
 * Serving the dev server from that host rather than rewriting the header in the
 * proxy is deliberate. A rewrite would let the app work at an origin the real
 * gateway would reject, which is exactly the class of "works in dev" that the
 * rule exists to prevent — and it would also put the session cookies on the
 * wrong origin, so the refresh path would be untestable locally.
 *
 * `*.localhost` resolves to loopback natively on macOS and in Chrome, and both
 * treat it as a secure context, so the `Secure` refresh and CSRF cookies are
 * accepted over plain HTTP without an exception anywhere.
 */
const DEV_HOST = process.env.ENCLAVE_DEV_HOST ?? 'tenant-alpha.localhost';
const API_TARGET = process.env.ENCLAVE_API_TARGET ?? 'http://127.0.0.1:8080';

export default defineConfig({
  /* Served from the origin root behind the gateway. The self-hosted `@font-face`
   * URLs in `src/styles/fonts.css` are absolute `/fonts/…` paths, so this and
   * they have to agree. */
  base: '/',
  server: {
    host: DEV_HOST,
    port: Number(process.env.ENCLAVE_DEV_PORT ?? 5173),
    /* Fail rather than drift to the next free port. A dev server that silently
     * moves is one whose origin no longer matches the cookies the API set, and
     * the symptom is a session that stops surviving reloads for no visible
     * reason. */
    strictPort: true,
    proxy: {
      /* Same-origin, so `credentials: 'same-origin'` in `shared/api` keeps
       * working and no CORS relaxation exists to be copied into production. */
      '/api': {
        target: API_TARGET,
        /* `false` keeps the browser's own `Host` on the forwarded request,
         * which is the whole point: the tenant label the API reads is the one
         * the user actually reached, not one this file invented. */
        changeOrigin: false,
      },
    },
  },
  build: {
    /* `tools/check-bundle-size.mjs` walks this to tell an initial chunk from a
     * lazy one. Without it the gate cannot compute the initial payload and
     * refuses to pass rather than measuring the wrong thing. */
    manifest: true,
    /* Warn early rather than at the gate. The gate is `tools/check-bundle-size.mjs`. */
    chunkSizeWarningLimit: 250,
    rollupOptions: {
      output: {
        /* Stable names so the budget check can name what it measured, and so a
         * regression report says which chunk grew rather than which hash changed. */
        entryFileNames: 'assets/[name].[hash].js',
        chunkFileNames: 'assets/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash][extname]',
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['tests/unit/**/*.test.{ts,tsx}'],
    globals: false,
    /* Unmounts between tests. Without it every `render()` stacked into one
     * document and absence assertions were evaluated against other tests' DOM
     * — see the file for what that cost. */
    setupFiles: ['./tests/setup.ts'],
    restoreMocks: true,
  },
  plugins: [react()],
});
