// SPDX-License-Identifier: AGPL-3.0-only

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { type Config, SESSION_COOKIE, STATE_COOKIE, type VocdoniAuth, vocdoniAuth } from '../src/index.js';
import { Keyring, serializeState } from '../src/cookie.js';
import { FakeOP } from './fakeop.js';

const APP = 'http://mytool.test';
const silent = { warn: () => {} };
const key = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) & 0xff);

let op: FakeOP;
let offset = 0; // ms added to the kit's clock

beforeEach(async () => {
  op = await new FakeOP().start();
  offset = 0;
});
afterEach(async () => {
  await op.stop();
});

function makeAuth(over: Partial<Config> = {}): VocdoniAuth {
  return vocdoniAuth({
    issuer: op.issuer,
    clientId: 'mytool',
    clientSecret: 's3cret',
    redirectUrl: `${APP}/auth/callback`,
    cookieKeys: [key(7)],
    insecure: true, // the fake provider is plain http on 127.0.0.1
    logger: silent,
    now: () => Date.now() + offset,
    ...over,
  });
}

function req(
  path: string,
  init: { method?: string; accept?: string; cookies?: Record<string, string>; headers?: Record<string, string> } = {},
): Request {
  const headers = new Headers(init.headers ?? {});
  if (init.accept) headers.set('Accept', init.accept);
  const c = Object.entries(init.cookies ?? {}).map(([k, v]) => `${k}=${v}`).join('; ');
  if (c) headers.set('Cookie', c);
  return new Request(`${APP}${path}`, { method: init.method ?? 'GET', headers });
}

/** name -> {value, attrs} for every Set-Cookie of a response. */
function setCookies(res: Response): Map<string, { value: string; attrs: string }> {
  const m = new Map<string, { value: string; attrs: string }>();
  for (const line of res.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split('; ');
    const eq = pair!.indexOf('=');
    m.set(pair!.slice(0, eq), { value: pair!.slice(eq + 1), attrs: attrs.join('; ') });
  }
  return m;
}

async function errorCode(res: Response): Promise<string> {
  return ((await res.json()) as { error: string }).error;
}

async function login(auth: VocdoniAuth, returnTo = '/') {
  const res = (await auth.handle(req(`/auth/login?return_to=${encodeURIComponent(returnTo)}`, { accept: 'text/html' })))!;
  expect(res.status).toBe(302);
  const state = setCookies(res).get(STATE_COOKIE)!;
  return { authUrl: res.headers.get('Location')!, state: state.value, stateAttrs: state.attrs };
}

async function signIn(auth: VocdoniAuth, returnTo = '/') {
  const { authUrl, state } = await login(auth, returnTo);
  const { code, state: st } = op.authorize(authUrl);
  return (await auth.handle(req(`/auth/callback?code=${code}&state=${st}`, { cookies: { [STATE_COOKIE]: state } })))!;
}

describe('flow', () => {
  it('signs in (happy path)', async () => {
    const auth = makeAuth();
    const { authUrl, state, stateAttrs } = await login(auth, '/docs?x=1');
    expect(authUrl.startsWith(`${op.issuer}/auth?`)).toBe(true);
    expect(stateAttrs).toBe('Path=/; Max-Age=600; HttpOnly; SameSite=Lax');
    const q = new URL(authUrl).searchParams;
    expect(q.get('state')).toHaveLength(43);
    expect(q.get('nonce')).toHaveLength(43);
    expect(q.get('redirect_uri')).toBe(`${APP}/auth/callback`);
    const { code, state: st } = op.authorize(authUrl);
    const res = (await auth.handle(req(`/auth/callback?code=${code}&state=${st}`, { cookies: { [STATE_COOKIE]: state } })))!;
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/docs?x=1');
    const cookies = setCookies(res);
    expect(cookies.get(STATE_COOKIE)?.attrs).toContain('Max-Age=0');
    const session = cookies.get(SESSION_COOKIE)!;
    expect(session.attrs).toBe('Path=/; Max-Age=43200; HttpOnly; SameSite=Lax');
    expect(auth.user(req('/x', { cookies: { [SESSION_COOKIE]: session.value } }))).toEqual({
      subject: 'CiQxMjM0',
      email: 'alice@vocdoni.org',
      name: 'Alice Example',
    });
  });

  it('marks cookies Secure unless insecure', () => {
    // The flow tests run insecure (plain-http fake provider); the attribute
    // itself is covered by serializeCookie in cookie.test.ts. Here: challenge()
    // clearing a stale cookie on a secure instance.
    const auth = makeAuth({ insecure: false, issuer: 'https://oauth.example', redirectUrl: `https://mytool.test/auth/callback` });
    const res = auth.challenge(req('/x', { cookies: { [SESSION_COOKIE]: 'garbage' } }));
    expect(res.headers.getSetCookie()[0]).toBe('vocauth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
  });

  it('returns null for other paths', async () => {
    expect(await makeAuth().handle(req('/other'))).toBeNull();
  });
});

describe('challenge (Require)', () => {
  it('redirects browsers and answers 401 otherwise', async () => {
    const auth = makeAuth();
    let res = auth.challenge(req('/docs?a=1&b=%2F', { accept: 'text/html,application/xhtml+xml' }));
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/auth/login?return_to=%2Fdocs%3Fa%3D1%26b%3D%252F');
    expect(auth.challenge(req('/docs', { method: 'HEAD', accept: 'text/html' })).status).toBe(302);
    for (const [method, accept] of [['GET', 'application/json'], ['GET', ''], ['POST', 'text/html']] as const) {
      res = auth.challenge(req('/api/x', { method, accept }));
      expect(res.status).toBe(401);
      expect(res.headers.get('WWW-Authenticate')).toBe('Cookie realm="mytool"');
      expect(await errorCode(res)).toBe('unauthenticated');
    }
  });
});

describe('session cookie', () => {
  it('treats tampered, garbage, unknown-key and expired cookies as signed out and clears them', async () => {
    const auth = makeAuth();
    const session = setCookies(await signIn(auth)).get(SESSION_COOKIE)!.value;
    const tampered = session.slice(0, 20) + (session[20] === 'A' ? 'B' : 'A') + session.slice(21);
    for (const v of [tampered, '%%%']) {
      const r = req('/x', { cookies: { [SESSION_COOKIE]: v } });
      expect(auth.user(r)).toBeNull();
      expect(auth.challenge(r).headers.getSetCookie()[0]).toContain('vocauth_session=; Path=/; Max-Age=0');
    }
    expect(makeAuth({ cookieKeys: [key(9)] }).user(req('/x', { cookies: { [SESSION_COOKIE]: session } }))).toBeNull();
    offset = (12 * 3600 + 1) * 1000;
    expect(auth.user(req('/x', { cookies: { [SESSION_COOKIE]: session } }))).toBeNull();
  });

  it('keeps sessions across staged key rotation', async () => {
    const before = makeAuth();
    const session = setCookies(await signIn(before)).get(SESSION_COOKIE)!.value;
    const rotated = makeAuth({ cookieKeys: [key(8), key(7)] });
    expect(rotated.user(req('/x', { cookies: { [SESSION_COOKIE]: session } }))).not.toBeNull();
    const fresh = setCookies(await signIn(rotated)).get(SESSION_COOKIE)!.value;
    expect(before.user(req('/x', { cookies: { [SESSION_COOKIE]: fresh } }))).toBeNull();
  });
});

describe('callback refusals', () => {
  const now = () => Math.floor(Date.now() / 1000);
  const cases: [string, (op: FakeOP) => void, number, string][] = [
    ['wrong audience', (o) => (o.mutate = (c) => void (c.aud = 'othertool')), 403, 'token'],
    ['wrong issuer', (o) => (o.mutate = (c) => void (c.iss = 'https://evil.example')), 403, 'token'],
    ['wrong nonce', (o) => (o.mutate = (c) => void (c.nonce = 'other')), 403, 'token'],
    ['missing nonce', (o) => (o.mutate = (c) => void delete c.nonce), 403, 'token'],
    ['expired beyond skew', (o) => (o.mutate = (c) => void (c.exp = now() - 90)), 403, 'token'],
    ['expired within skew', (o) => (o.mutate = (c) => void (c.exp = now() - 30)), 303, ''],
    ['signed by another key', (o) => void (o.rogue = true), 403, 'token'],
    ['no id_token', (o) => void (o.noIdToken = true), 403, 'token'],
    ['email not verified', (o) => (o.mutate = (c) => void (c.email_verified = false)), 403, 'domain'],
    ['email_verified missing', (o) => (o.mutate = (c) => void delete c.email_verified), 403, 'domain'],
    ['email missing', (o) => (o.mutate = (c) => void delete c.email), 403, 'domain'],
    ['disallowed domain', (o) => (o.mutate = (c) => void (c.email = 'bob@example.com')), 403, 'domain'],
    ['lookalike domain', (o) => (o.mutate = (c) => void (c.email = 'bob@vocdoni.org.example.com')), 403, 'domain'],
    ['token endpoint error', (o) => void (o.tokenStatus = 400), 403, 'exchange'],
  ];
  it.each(cases)('%s', async (_name, setup, status, code) => {
    const auth = makeAuth();
    const { authUrl, state } = await login(auth);
    const { code: c, state: st } = op.authorize(authUrl);
    setup(op);
    const res = (await auth.handle(req(`/auth/callback?code=${c}&state=${st}`, { cookies: { [STATE_COOKIE]: state } })))!;
    expect(res.status).toBe(status);
    const cookies = setCookies(res);
    expect(cookies.get(STATE_COOKIE)?.attrs).toContain('Max-Age=0');
    if (code) {
      expect(await errorCode(res)).toBe(code);
      expect(cookies.has(SESSION_COOKIE)).toBe(false);
    }
  });
});

describe('state refusals', () => {
  it('refuses wrong, missing or foreign state and clears the state cookie', async () => {
    const auth = makeAuth();
    const { authUrl, state } = await login(auth);
    const { code, state: st } = op.authorize(authUrl);
    const ring = new Keyring([key(7)]);
    const other = ring.seal(STATE_COOKIE, serializeState({ state: 'x', nonce: 'y', code_verifier: 'z', return_to: '/', iat: Math.floor(Date.now() / 1000) }));
    const cases: [string, string, string | undefined][] = [
      ['state mismatch', `code=${code}&state=wrong`, state],
      ['state param missing', `code=${code}`, state],
      ['state cookie missing', `code=${code}&state=${st}`, undefined],
      ['state cookie from another login', `code=${code}&state=${st}`, other],
      ['session value as state', `code=${code}&state=${st}`, ring.seal(SESSION_COOKIE, '{}')],
    ];
    for (const [name, query, cookie] of cases) {
      const res = (await auth.handle(req(`/auth/callback?${query}`, { cookies: cookie ? { [STATE_COOKIE]: cookie } : {} })))!;
      expect(res.status, name).toBe(403);
      expect(await errorCode(res), name).toBe('state');
      expect(setCookies(res).get(STATE_COOKIE)?.attrs, name).toContain('Max-Age=0');
    }
    offset = 601_000;
    const res = (await auth.handle(req(`/auth/callback?code=${code}&state=${st}`, { cookies: { [STATE_COOKIE]: state } })))!;
    expect(await errorCode(res)).toBe('state');
  });
});

describe('provider error', () => {
  it('answers a plain page without reflecting provider strings', async () => {
    const auth = makeAuth();
    const { authUrl, state } = await login(auth);
    const st = new URL(authUrl).searchParams.get('state')!;
    const res = (await auth.handle(
      req(`/auth/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=${st}`, {
        accept: 'text/html',
        cookies: { [STATE_COOKIE]: state },
      }),
    ))!;
    const body = await res.text();
    expect(res.status).toBe(403);
    expect(res.headers.get('Content-Type')).toMatch(/^text\/html/);
    expect(body).toContain('Error code: provider');
    expect(body).not.toContain('script');
    expect(body).not.toContain('access_denied');
  });
});

describe('open redirect', () => {
  it.each(['//evil.com', '/\\evil.com', 'https://evil.com', '/\t/evil.com', 'evil.com', '', '\\\\evil.com',
    '/\u2028x', '/a/../b', '/x\\y'])(
    'return_to %j lands on /',
    async (v) => {
      const res = await signIn(makeAuth(), v);
      expect(res.status).toBe(303);
      expect(res.headers.get('Location')).toBe('/');
    },
  );
});

describe('logout', () => {
  it('is POST only', async () => {
    const auth = makeAuth();
    let res = (await auth.handle(req('/auth/logout', { accept: 'text/html' })))!;
    expect(res.status).toBe(405);
    expect(res.headers.get('Allow')).toBe('POST');
    expect(res.headers.getSetCookie()).toEqual([]);
    res = (await auth.handle(req('/auth/logout', { method: 'POST', headers: { Origin: APP } })))!;
    expect(res.status).toBe(303);
    expect(res.headers.get('Location')).toBe('/');
    expect(setCookies(res).get(SESSION_COOKIE)?.attrs).toContain('Max-Age=0');
  });

  it('requires a same-origin POST (Origin, else Sec-Fetch-Site)', async () => {
    const auth = makeAuth();
    const cookies = { [SESSION_COOKIE]: setCookies(await signIn(auth)).get(SESSION_COOKIE)!.value };
    const refused: Record<string, string>[] = [{}, { Origin: 'http://evil.test' }, { Origin: 'null' },
      { 'Sec-Fetch-Site': 'cross-site' }, { Origin: 'http://evil.test', 'Sec-Fetch-Site': 'same-origin' }];
    for (const headers of refused) {
      const res = (await auth.handle(req('/auth/logout', { method: 'POST', cookies, headers })))!;
      expect(res.status, JSON.stringify(headers)).toBe(403);
      expect(await errorCode(res)).toBe('origin');
      expect(res.headers.getSetCookie()).toEqual([]); // the session stays
    }
    const accepted: Record<string, string>[] = [{ Origin: APP }, { 'Sec-Fetch-Site': 'same-origin' }, { Origin: APP, 'Sec-Fetch-Site': 'same-origin' }];
    for (const headers of accepted) {
      const res = (await auth.handle(req('/auth/logout', { method: 'POST', cookies, headers })))!;
      expect(res.status, JSON.stringify(headers)).toBe(303);
      expect(res.headers.get('Location')).toBe('/');
      expect(setCookies(res).get(SESSION_COOKIE)?.attrs).toContain('Max-Age=0');
    }
  });
});

describe('issuer down at start', () => {
  it('constructs, answers 503, backs off, then recovers', async () => {
    op.down = true;
    const auth = makeAuth();
    let res = (await auth.handle(req('/auth/login', { accept: 'application/json' })))!;
    expect(res.status).toBe(503);
    expect(await errorCode(res)).toBe('sso_unavailable');
    op.down = false;
    res = (await auth.handle(req('/auth/login')))!;
    expect(res.status).toBe(503); // still backing off: the issuer is not contacted
    offset = 2000;
    res = (await auth.handle(req('/auth/login')))!;
    expect(res.status).toBe(302);
  });
});

describe('limiter and methods', () => {
  it('limits login and callback', async () => {
    let calls = 0;
    const auth = makeAuth({ limiter: () => (calls++, false) });
    for (const p of ['/auth/login', '/auth/callback?state=x&code=y']) {
      const res = (await auth.handle(req(p)))!;
      expect(res.status).toBe(429);
      expect(await errorCode(res)).toBe('rate_limited');
    }
    expect(calls).toBe(2);
  });

  it('answers 405 for non-GET login and callback', async () => {
    const auth = makeAuth();
    for (const p of ['/auth/login', '/auth/callback']) {
      const res = (await auth.handle(req(p, { method: 'POST' })))!;
      expect(res.status).toBe(405);
      expect(res.headers.get('Allow')).toBe('GET');
    }
  });
});
