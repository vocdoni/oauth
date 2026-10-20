// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { FIXTURE_DIR, verifyFixtureFile } from './fixtures.js';

describe('cross-kit cookie fixtures', () => {
  it('opens, re-serialises and re-seals every cookie the Go kit produced', () => {
    verifyFixtureFile(`${FIXTURE_DIR}go.json`);
  });

  it('matches the Go fixture case for case', () => {
    const strip = (p: string) => {
      const f = JSON.parse(readFileSync(`${FIXTURE_DIR}${p}`, 'utf8')) as { generator: string };
      const { generator, ...rest } = f;
      return { generator, rest };
    };
    const go = strip('go.json');
    const node = strip('node.json');
    expect([go.generator, node.generator]).toEqual(['go', 'node']);
    expect(node.rest).toEqual(go.rest);
  });
});
