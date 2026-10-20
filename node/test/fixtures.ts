// SPDX-License-Identifier: AGPL-3.0-only
//
// Cross-kit cookie fixture helpers (shared by cookie.test.ts and crosskit.test.ts).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect } from 'vitest';
import {
  Keyring,
  SESSION_COOKIE,
  STATE_COOKIE,
  type SessionPayload,
  type StatePayload,
  serializeSession,
  serializeState,
} from '../src/cookie.js';

// Cross-kit cookie fixtures live in the Go module so that it stays
// self-contained: go/testdata/cookies/{go,node}.json. `npm run fixtures`
// rewrites node.json; the Go kit writes go.json. Both kits verify both files.
export const FIXTURE_DIR = fileURLToPath(new URL('../../go/testdata/cookies/', import.meta.url));

interface FixtureCase {
  name: string;
  cookie: string;
  sealKey: number;
  nonce: string;
  payload: string;
  value: string;
}
interface FixtureFile {
  format: string;
  generator: string;
  keys: string[];
  cases: FixtureCase[];
  invalid: { name: string; cookie: string; value: string }[];
}

export const seq = (start: number, n: number) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

export function buildFixture(): FixtureFile {
  const keyA = seq(0x00, 32);
  const keyB = seq(0x20, 32);
  const keyC = seq(0x40, 32);
  const f: FixtureFile = {
    format: 'vocauth-cookie-v1',
    generator: 'node',
    keys: [Buffer.from(keyA).toString('base64'), Buffer.from(keyB).toString('base64')],
    cases: [],
    invalid: [],
  };
  const session = serializeSession({ sub: 'CiQxMjM0NTY3ODkw', email: 'alice@vocdoni.org', name: 'Alice Example', iat: 1760954400, exp: 1760997600 });
  const unicode = serializeSession({ sub: 'u-2', email: 'nuria@vocdoni.org', name: 'Núria Ñúñez & <Co> "Q" \\ é', iat: 1760954400, exp: 1760997600 });
  const state = serializeState({
    state: 'c3RhdGUtc3RhdGUtc3RhdGUtc3RhdGUtc3RhdGUtc3Q',
    nonce: 'bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm8',
    code_verifier: 'dmVyaWZpZXItdmVyaWZpZXItdmVyaWZpZXItdmVyaWZp',
    return_to: '/docs?x=1&y=%2F',
    iat: 1760954400,
  });
  const add = (name: string, cookie: string, sealKey: number, nonce: Uint8Array, payload: string) => {
    const value = new Keyring([[keyA, keyB][sealKey]!]).sealWithNonce(cookie, payload, nonce);
    f.cases.push({ name, cookie, sealKey, nonce: Buffer.from(nonce).toString('hex'), payload, value });
    return value;
  };
  const sessionValue = add('session', SESSION_COOKIE, 0, seq(0x80, 12), session);
  add('state', STATE_COOKIE, 0, seq(0x90, 12), state);
  add('session-rotated-key', SESSION_COOKIE, 1, seq(0xa0, 12), session);
  add('session-unicode', SESSION_COOKIE, 0, seq(0xb0, 12), unicode);

  const raw = Buffer.from(sessionValue, 'base64url');
  raw[Math.floor(raw.length / 2)]! ^= 0x01;
  f.invalid = [
    { name: 'tampered', cookie: SESSION_COOKIE, value: raw.toString('base64url') },
    { name: 'wrong-cookie-name', cookie: STATE_COOKIE, value: sessionValue },
    { name: 'unknown-key', cookie: SESSION_COOKIE, value: new Keyring([keyC]).sealWithNonce(SESSION_COOKIE, session, seq(0xc0, 12)) },
    { name: 'truncated', cookie: SESSION_COOKIE, value: sessionValue.slice(0, 30) },
    { name: 'not-base64url', cookie: SESSION_COOKIE, value: 'a+b/c==' },
    { name: 'empty', cookie: SESSION_COOKIE, value: '' },
    { name: 'too-long', cookie: SESSION_COOKIE, value: 'A'.repeat(4097) },
  ];
  return f;
}

/** Checks every case of a fixture file produced by either kit. */
export function verifyFixtureFile(path: string): void {
  const f = JSON.parse(readFileSync(path, 'utf8')) as FixtureFile;
  expect(f.format).toBe('vocauth-cookie-v1');
  expect(f.cases.length).toBeGreaterThan(0);
  const keys = f.keys.map((k) => new Uint8Array(Buffer.from(k, 'base64')));
  const ring = new Keyring(keys);
  for (const c of f.cases) {
    expect(ring.open(c.cookie, c.value), `${f.generator}/${c.name} open`).toBe(c.payload);
    const parsed = JSON.parse(c.payload) as SessionPayload & StatePayload;
    const re = c.cookie === SESSION_COOKIE ? serializeSession(parsed) : serializeState(parsed);
    expect(re, `${f.generator}/${c.name} re-serialised`).toBe(c.payload);
    const sealed = new Keyring([keys[c.sealKey]!]).sealWithNonce(c.cookie, c.payload, Buffer.from(c.nonce, 'hex'));
    expect(sealed, `${f.generator}/${c.name} byte-identical seal`).toBe(c.value);
  }
  for (const c of f.invalid) {
    expect(ring.open(c.cookie, c.value), `${f.generator}/invalid ${c.name}`).toBeNull();
  }
}
