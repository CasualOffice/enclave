/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/* Vite is the bundler because the shell is a static SPA served by the Rust
 * gateway: there is no server runtime to justify Next.js, its Rollup build
 * gives the deterministic named chunks `check:bundle-size` measures against
 * `docs/09 §2`'s 250 KB budget, and Vitest reuses this exact transform
 * pipeline so tests and the shipped bundle cannot diverge. */
export default defineConfig({
  /* Served from the origin root behind the gateway. The self-hosted `@font-face`
   * URLs in `src/styles/fonts.css` are absolute `/fonts/…` paths, so this and
   * they have to agree. */
  base: '/',
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
