// SPDX-License-Identifier: AGPL-3.0-only
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
  resolve: {
    // examples/express/app.js imports the published names; resolve them to
    // this checkout so the example is tested against the current source.
    alias: {
      '@vocdoni/oauth': here('./src/index.ts'),
      express: here('./node_modules/express/index.js'),
    },
  },
});
