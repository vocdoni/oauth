// SPDX-License-Identifier: AGPL-3.0-only

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// The Express example from examples/express (aliases in vitest.config.ts).
import { createApp, createLimiter } from '../../examples/express/app.js';
import { STATE_COOKIE, SESSION_COOKIE, vocdoniAuth } from '../src/index.js';
import { FakeOP } from './fakeop.js';

let op: FakeOP;
let server: Server;
let base: string;

beforeEach(async () => {
  op = await new FakeOP().start();
  const auth = vocdoniAuth({
    issuer: op.issuer,
    clientId: 'mytool',
    clientSecret: 's3cret',
    redirectUrl: 'http://mytool.test/auth/callback',
    cookieKeys: [new Uint8Array(32).fill(5)],
    insecure: true,
    logger: { warn: () => {} },
  });
  server = createApp(auth).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  await op.stop();
});

const get = (path: string, init: RequestInit = {}) => fetch(`${base}${path}`, { redirect: 'manual', ...init });
const cookieOf = (res: Response, name: string) =>
  res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`))?.split(';')[0]!.slice(name.length + 1);

describe('Express example', () => {
  it('signs in, serves the user, signs out', async () => {
    let res = await get('/', { headers: { Accept: 'text/html' } });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/auth/login?return_to=%2F');

    res = await get('/api/me', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Cookie realm="mytool"');

    res = await get('/auth/login?return_to=%2Fapi%2Fme');
    expect(res.status).toBe(302);
    const state = cookieOf(res, STATE_COOKIE)!;
    const { code, state: st } = op.authorize(res.headers.get('location')!);

    res = await get(`/auth/callback?code=${code}&state=${st}`, { headers: { Cookie: `${STATE_COOKIE}=${state}` } });
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/api/me');
    const session = cookieOf(res, SESSION_COOKIE)!;
    expect(res.headers.getSetCookie()).toHaveLength(2); // state cleared + session set

    res = await get('/api/me', { headers: { Cookie: `${SESSION_COOKIE}=${session}` } });
    expect(await res.json()).toEqual({ subject: 'CiQxMjM0', email: 'alice@vocdoni.org', name: 'Alice Example' });
    res = await get('/', { headers: { Cookie: `${SESSION_COOKIE}=${session}` } });
    expect(await res.text()).toContain('Signed in as Alice Example (alice@vocdoni.org)');

    expect((await get('/auth/logout')).status).toBe(405);
    res = await get('/auth/logout', { method: 'POST', headers: { Cookie: `${SESSION_COOKIE}=${session}`, Origin: 'http://evil.test' } });
    expect(res.status).toBe(403); // cross-site form posts never sign the user out
    res = await get('/auth/logout', { method: 'POST', headers: { Cookie: `${SESSION_COOKIE}=${session}`, Origin: 'http://mytool.test' } });
    expect(res.status).toBe(303);
    expect(res.headers.getSetCookie()[0]).toContain(`${SESSION_COOKIE}=; Path=/; Max-Age=0`);
  });

  it('limits per client IP', () => {
    const allow = createLimiter(2, 60_000);
    const r = new Request('http://x/auth/login');
    expect([allow(r, { ip: 'a' }), allow(r, { ip: 'a' }), allow(r, { ip: 'a' }), allow(r, { ip: 'b' })]).toEqual([true, true, false, true]);
  });
});
