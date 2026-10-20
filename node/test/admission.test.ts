// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { admit, sanitizeReturnTo } from '../src/admission.js';
import { resolveConfig } from '../src/config.js';

// The keep and drop tables are the same in go/admission_test.go.
describe('sanitizeReturnTo', () => {
  it('keeps relative paths', () => {
    const keep = ['/', '/a', '/docs?x=1&y=%2F', '/ui/', '/%2F%2Fevil.com', '/ok/path?x=1',
      '/..%5Cevil', '/%0d%0a', '/a?next=/../b', '/a#/../b', '/.well-known/x', '/a.b/c..d/...',
      `/${'a'.repeat(2047)}`];
    for (const s of keep) expect(sanitizeReturnTo(s), JSON.stringify(s)).toBe(s);
  });
  it('drops everything else', () => {
    const drop = ['', '//evil.com', '/\\evil.com', 'https://evil.com', 'evil.com',
      '/\t/evil.com', '/\n/evil.com', '/\r\n/x', '\\/evil.com', '/x\x7f', ' /a',
      `/${'a'.repeat(2048)}`,
      // backslash anywhere
      '/../\\evil.example', '/x\\y', '/\\x', '/a?x=\\',
      // "." and ".." path segments, literal or %2e-encoded
      '/a/../b', '/./x', '/a/..', '/a/.', '/a/./?x=1', '/a/..#f', '/%2e%2e/x', '/a/.%2E/b', '/%2E',
      // other slash and control variants
      '//x', '/x\ty', '/x\r', '/x\n', '/\t/x',
      // not printable ASCII (a Fetch Location header cannot hold > U+00FF)
      '/caf\u00e9', '/\u2028x', '/\u65e5\u672c'];
    for (const s of drop) expect(sanitizeReturnTo(s), JSON.stringify(s)).toBe('/');
    expect(sanitizeReturnTo(null)).toBe('/');
  });
});

describe('admit', () => {
  const domains = ['vocdoni.org'];
  const emails = ['guest@example.com'];
  const cases: [unknown, unknown, string | null][] = [
    ['alice@vocdoni.org', true, 'alice@vocdoni.org'],
    ['Alice@VOCDONI.org', true, 'alice@vocdoni.org'],
    ['alice@vocdoni.org', false, null],
    ['alice@vocdoni.org', 'true', null],
    ['alice@vocdoni.org', undefined, null],
    ['', true, null],
    [undefined, true, null],
    ['bob@example.com', true, null],
    ['guest@example.com', true, 'guest@example.com'],
    ['GUEST@example.com', true, 'guest@example.com'],
    ['alice@sub.vocdoni.org', true, null],
    ['alice@vocdoni.org.evil.com', true, null],
    ['a@b@vocdoni.org', true, 'a@b@vocdoni.org'],
    ['@vocdoni.org', true, null],
    ['vocdoni.org', true, null],
  ];
  it.each(cases)('admit(%j, %j) = %j', (email, verified, want) => {
    expect(admit(email, verified, domains, emails)).toBe(want);
  });
});

describe('resolveConfig', () => {
  const good = {
    issuer: 'https://oauth.vocdoni.org',
    clientId: 'mytool',
    clientSecret: 's',
    redirectUrl: 'https://mytool.vocdoni.io/auth/callback',
    cookieKeys: [new Uint8Array(32)],
  };
  it('applies defaults', () => {
    const c = resolveConfig(good);
    expect(c.maxAge).toBe(43200);
    expect(c.allowedDomains).toEqual(['vocdoni.org']);
  });
  it('does not add the default domain when only emails are set', () => {
    const c = resolveConfig({ ...good, allowedEmails: ['Guest@Example.com'] });
    expect(c.allowedDomains).toEqual([]);
    expect(c.allowedEmails).toEqual(['guest@example.com']);
  });
  it.each([
    { issuer: '' },
    { issuer: 'http://oauth.vocdoni.org' },
    { redirectUrl: '/auth/callback' },
    { clientId: '' },
    { clientId: 'a"b' },
    { clientSecret: '' },
    { cookieKeys: [] },
    { cookieKeys: [new Uint8Array(16)] },
    { maxAge: 8 * 24 * 3600 },
    { maxAge: -1 },
    { allowedDomains: ['a@b'] },
    { allowedEmails: ['nobody'] },
  ])('rejects %j', (bad) => {
    expect(() => resolveConfig({ ...good, ...bad })).toThrow(/vocauth: invalid configuration/);
  });
  it('allows http with insecure', () => {
    expect(() =>
      resolveConfig({ ...good, insecure: true, issuer: 'http://localhost:5556', redirectUrl: 'http://localhost:8080/auth/callback' }),
    ).not.toThrow();
  });
});
