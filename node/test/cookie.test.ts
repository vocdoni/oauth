// SPDX-License-Identifier: AGPL-3.0-only

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Keyring, SESSION_COOKIE, STATE_COOKIE, parseCookieKeys, readCookie, serializeCookie } from '../src/cookie.js';
import { FIXTURE_DIR, buildFixture, seq, verifyFixtureFile } from './fixtures.js';

describe('cookie fixtures', () => {
  it('node.json is current and verifies', () => {
    const path = `${FIXTURE_DIR}node.json`;
    const want = `${JSON.stringify(buildFixture(), null, 2)}\n`;
    if (process.env.UPDATE_FIXTURES === '1') {
      mkdirSync(FIXTURE_DIR, { recursive: true });
      writeFileSync(path, want);
    }
    expect(readFileSync(path, 'utf8'), 'node.json is stale: run npm run fixtures').toBe(want);
    verifyFixtureFile(path);
  });
});

describe('keyring', () => {
  it('opens cookies sealed with a rotated-out first key, not after removal', () => {
    const oldKey = seq(1, 32);
    const newKey = seq(2, 32);
    const v = new Keyring([oldKey]).seal(SESSION_COOKIE, '{"x":1}');
    expect(new Keyring([newKey, oldKey]).open(SESSION_COOKIE, v)).toBe('{"x":1}');
    expect(new Keyring([newKey]).open(SESSION_COOKIE, v)).toBeNull();
    expect(new Keyring([newKey, oldKey]).open(STATE_COOKIE, v)).toBeNull();
  });

  it('never reuses a nonce', () => {
    const k = new Keyring([seq(3, 32)]);
    expect(k.seal(SESSION_COOKIE, 'p')).not.toBe(k.seal(SESSION_COOKIE, 'p'));
  });

  it('rejects keys of the wrong size', () => {
    expect(() => new Keyring([seq(0, 16)])).toThrow();
    expect(() => new Keyring([])).toThrow();
  });
});

describe('cookie helpers', () => {
  it('serialises attributes like the Go kit', () => {
    expect(serializeCookie('vocauth_state', 'v', { maxAge: 600, secure: true })).toBe(
      'vocauth_state=v; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax',
    );
    expect(serializeCookie('vocauth_session', '', { maxAge: 0, secure: false })).toBe(
      'vocauth_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax',
    );
  });

  it('reads the first matching cookie', () => {
    expect(readCookie('a=1; vocauth_session=xyz; vocauth_session=2', 'vocauth_session')).toBe('xyz');
    expect(readCookie('a=1', 'vocauth_session')).toBeNull();
    expect(readCookie(null, 'a')).toBeNull();
  });

  it('parses cookie keys', () => {
    const a = seq(0, 32);
    const b = seq(0x20, 32);
    const keys = parseCookieKeys(`${Buffer.from(a).toString('base64')} , ${Buffer.from(b).toString('base64url')}`);
    expect(keys.map((k) => Buffer.from(k).toString('hex'))).toEqual([Buffer.from(a).toString('hex'), Buffer.from(b).toString('hex')]);
    for (const bad of ['', 'abc', Buffer.alloc(16).toString('base64'), '!!!!']) {
      expect(() => parseCookieKeys(bad), bad).toThrow();
    }
  });
});
