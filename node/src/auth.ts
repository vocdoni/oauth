// SPDX-License-Identifier: AGPL-3.0-only

import { timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import * as client from 'openid-client';
import { admit, sanitizeReturnTo } from './admission.js';
import { type Config, type RequestContext, type ResolvedConfig, resolveConfig } from './config.js';
import {
  Keyring,
  SESSION_COOKIE,
  STATE_COOKIE,
  type SessionPayload,
  type StatePayload,
  randomToken,
  readCookie,
  serializeCookie,
  serializeSession,
  serializeState,
} from './cookie.js';
import { toRequest, writeResponse } from './node-http.js';

export interface User {
  subject: string;
  email: string; // lower-cased
  name: string;
}

/** An Express (or plain node:http) request after require(): req.user is set. */
export type AuthRequest = IncomingMessage & { originalUrl?: string; ip?: string; user?: User };
export type Middleware = (req: AuthRequest, res: ServerResponse, next: (err?: unknown) => void) => void;

const STATE_MAX_AGE = 600;
const CLOCK_SKEW = 60;
const MIN_BACKOFF = 1000;
const MAX_BACKOFF = 60_000;
const HTTP_TIMEOUT = 10; // seconds

const MESSAGES: Record<string, string> = {
  state: 'The sign-in request expired or was started in another tab. Please try again.',
  exchange: 'The sign-in could not be completed with the identity provider. Please try again.',
  token: 'The identity provider returned an invalid sign-in token.',
  domain: 'This account is not allowed to use this tool.',
  provider: 'The identity provider refused the sign-in.',
  origin: 'The sign-out request did not come from this site. Use the sign-out button.',
  sso_unavailable: 'Single sign-on is unavailable right now. Please try again later.',
  rate_limited: 'Too many sign-in attempts. Please wait a minute and try again.',
};

function wantsHTML(req: Request): boolean {
  return (req.headers.get('accept') ?? '').includes('text/html');
}

function json(status: number, code: string, headers: Headers = new Headers()): Response {
  headers.set('Content-Type', 'application/json');
  headers.set('Cache-Control', 'no-store');
  return new Response(`${JSON.stringify({ error: code })}\n`, { status, headers });
}

function redirect(status: number, location: string, headers: Headers = new Headers()): Response {
  headers.set('Location', location);
  headers.set('Cache-Control', 'no-store');
  return new Response(null, { status, headers });
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function errorPage(code: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body><h1>Sign-in failed</h1><p>${MESSAGES[code] ?? ''}</p><p>Error code: ${code}</p><p><a href="/auth/login">Try again</a></p></body></html>
`;
}

/** Token-endpoint failures map to "exchange", ID token failures to "token". */
function isExchangeError(e: unknown): boolean {
  if (e instanceof client.ResponseBodyError || e instanceof TypeError) return true;
  if (e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError')) return true;
  if (e instanceof client.ClientError) {
    return e.code === 'OAUTH_RESPONSE_IS_NOT_CONFORM' || e.code === 'OAUTH_RESPONSE_IS_NOT_JSON';
  }
  return false;
}

export class VocdoniAuth {
  private readonly cfg: ResolvedConfig;
  private readonly keys: Keyring;
  private readonly origin: string; // of redirectUrl, as a browser writes Origin
  private oidc: client.Configuration | undefined;
  private pending: Promise<client.Configuration> | undefined;
  private nextTry = 0;
  private backoff = 0;

  /** Validates the configuration; performs no network I/O. */
  constructor(config: Config) {
    this.cfg = resolveConfig(config);
    this.keys = new Keyring(this.cfg.cookieKeys);
    this.origin = new URL(this.cfg.redirectUrl).origin;
  }

  /**
   * Whether a state-changing request comes from this tool's own origin: an
   * Origin header, when present, must equal the redirect URL's origin;
   * otherwise Sec-Fetch-Site must be same-origin. Neither header: refused.
   */
  private sameOrigin(req: Request): boolean {
    const origin = req.headers.get('origin');
    if (origin) return origin === this.origin;
    return req.headers.get('sec-fetch-site') === 'same-origin';
  }

  /**
   * Provider metadata, fetched on first use. A failure is retried on a later
   * call after an exponential backoff (1 s doubling to 1 min); while backing
   * off it fails fast. JWKS are fetched by openid-client on the first ID token
   * and refetched when an unknown kid appears.
   */
  private async discover(): Promise<client.Configuration> {
    if (this.oidc) return this.oidc;
    if (this.pending) return this.pending;
    const now = this.cfg.now();
    if (now < this.nextTry) throw new Error('vocauth: discovery is backing off after a failure');
    // openid-client skips the ID token signature check for tokens received
    // from the token endpoint over TLS (OIDC Core 3.1.3.7 (6) allows it);
    // enableNonRepudiationChecks makes it verify the signature against the
    // JWKS, as the spec requires and as go-oidc always does.
    const execute = [client.enableNonRepudiationChecks];
    if (this.cfg.insecure) execute.push(client.allowInsecureRequests);
    const options: client.DiscoveryRequestOptions = { timeout: HTTP_TIMEOUT, execute };
    if (this.cfg.fetch) options[client.customFetch] = this.cfg.fetch as client.CustomFetch;
    this.pending = client.discovery(
      new URL(this.cfg.issuer),
      this.cfg.clientId,
      { client_secret: this.cfg.clientSecret, [client.clockTolerance]: CLOCK_SKEW },
      client.ClientSecretBasic(this.cfg.clientSecret),
      options,
    );
    try {
      this.oidc = await this.pending;
      return this.oidc;
    } catch (e) {
      this.backoff = this.backoff === 0 ? MIN_BACKOFF : Math.min(2 * this.backoff, MAX_BACKOFF);
      this.nextTry = now + this.backoff;
      throw e;
    } finally {
      this.pending = undefined;
    }
  }

  private nowSeconds(): number {
    return Math.floor(this.cfg.now() / 1000);
  }

  private cookie(name: string, value: string, maxAge: number): string {
    return serializeCookie(name, value, { maxAge, secure: !this.cfg.insecure });
  }

  private clear(name: string): string {
    return this.cookie(name, '', 0);
  }

  private fail(req: Request, status: number, code: string, headers: Headers = new Headers()): Response {
    if (!wantsHTML(req)) return json(status, code, headers);
    headers.set('Content-Type', 'text/html; charset=utf-8');
    headers.set('Cache-Control', 'no-store');
    return new Response(errorPage(code), { status, headers });
  }

  private refuse(req: Request, headers: Headers, code: string, reason: string, attrs: Record<string, unknown> = {}): Response {
    this.cfg.logger.warn(`vocauth: sign-in refused: ${reason}`, { code, ...attrs });
    return this.fail(req, 403, code, headers);
  }

  private session(req: Request): { user: User | null; stale: boolean } {
    const value = readCookie(req.headers.get('cookie'), SESSION_COOKIE);
    if (value === null) return { user: null, stale: false };
    const pt = this.keys.open(SESSION_COOKIE, value);
    if (pt !== null) {
      try {
        const p = JSON.parse(pt) as Partial<SessionPayload>;
        if (typeof p.sub === 'string' && p.sub && typeof p.email === 'string' && p.email &&
            typeof p.exp === 'number' && p.exp > this.nowSeconds()) {
          return { user: { subject: p.sub, email: p.email, name: typeof p.name === 'string' ? p.name : '' }, stale: false };
        }
      } catch {
        // undecodable payload: signed out
      }
    }
    return { user: null, stale: true };
  }

  /** The signed-in user of a request, or null. */
  user(req: Request): User | null {
    return this.session(req).user;
  }

  /**
   * The answer for an unauthenticated request: 302 to /auth/login for GET/HEAD
   * accepting text/html, else 401 {"error":"unauthenticated"} with
   * WWW-Authenticate. Clears a stale session cookie.
   */
  challenge(req: Request): Response {
    const headers = new Headers();
    if (this.session(req).stale) headers.append('Set-Cookie', this.clear(SESSION_COOKIE));
    const url = new URL(req.url);
    if ((req.method === 'GET' || req.method === 'HEAD') && wantsHTML(req)) {
      const q = new URLSearchParams({ return_to: url.pathname + url.search });
      return redirect(302, `/auth/login?${q.toString()}`, headers);
    }
    headers.set('WWW-Authenticate', `Cookie realm="${this.cfg.clientId}"`);
    return json(401, 'unauthenticated', headers);
  }

  /**
   * Serves GET /auth/login, GET /auth/callback and POST /auth/logout; returns
   * null for any other path so the caller can continue.
   */
  async handle(req: Request, ctx?: RequestContext): Promise<Response | null> {
    const path = new URL(req.url).pathname;
    if (path === '/auth/login') return this.login(req, ctx);
    if (path === '/auth/callback') return this.callback(req, ctx);
    if (path === '/auth/logout') return this.logout(req);
    return null;
  }

  private methodNotAllowed(allow: string): Response {
    return json(405, 'method_not_allowed', new Headers({ Allow: allow }));
  }

  private async login(req: Request, ctx?: RequestContext): Promise<Response> {
    if (req.method !== 'GET') return this.methodNotAllowed('GET');
    if (this.cfg.limiter && !this.cfg.limiter(req, ctx)) return this.fail(req, 429, 'rate_limited');
    let oidc: client.Configuration;
    try {
      oidc = await this.discover();
    } catch (e) {
      this.cfg.logger.warn('vocauth: provider discovery failed', { err: String(e) });
      return this.fail(req, 503, 'sso_unavailable');
    }
    const st: StatePayload = {
      state: randomToken(),
      nonce: randomToken(),
      code_verifier: randomToken(), // 43 chars, RFC 7636
      return_to: sanitizeReturnTo(new URL(req.url).searchParams.get('return_to')),
      iat: this.nowSeconds(),
    };
    const target = client.buildAuthorizationUrl(oidc, {
      redirect_uri: this.cfg.redirectUrl,
      scope: 'openid email profile',
      state: st.state,
      nonce: st.nonce,
      code_challenge: await client.calculatePKCECodeChallenge(st.code_verifier),
      code_challenge_method: 'S256',
    });
    const headers = new Headers();
    headers.append('Set-Cookie', this.cookie(STATE_COOKIE, this.keys.seal(STATE_COOKIE, serializeState(st)), STATE_MAX_AGE));
    return redirect(302, target.href, headers);
  }

  private readState(req: Request): StatePayload | null {
    const value = readCookie(req.headers.get('cookie'), STATE_COOKIE);
    if (value === null) return null;
    const pt = this.keys.open(STATE_COOKIE, value);
    if (pt === null) return null;
    try {
      const st = JSON.parse(pt) as Partial<StatePayload>;
      const now = this.nowSeconds();
      if (typeof st.state !== 'string' || !st.state || typeof st.nonce !== 'string' || !st.nonce ||
          typeof st.code_verifier !== 'string' || !st.code_verifier || typeof st.iat !== 'number' ||
          st.iat > now + CLOCK_SKEW || now - st.iat > STATE_MAX_AGE) {
        return null;
      }
      return { ...(st as StatePayload), return_to: sanitizeReturnTo(st.return_to) };
    } catch {
      return null;
    }
  }

  private async callback(req: Request, ctx?: RequestContext): Promise<Response> {
    if (req.method !== 'GET') return this.methodNotAllowed('GET');
    if (this.cfg.limiter && !this.cfg.limiter(req, ctx)) return this.fail(req, 429, 'rate_limited');
    const st = this.readState(req);
    const headers = new Headers();
    headers.append('Set-Cookie', this.clear(STATE_COOKIE)); // whatever the outcome
    const params = new URL(req.url).searchParams;
    const state = params.get('state');
    if (!st || !state || !safeEqual(state, st.state)) {
      return this.refuse(req, headers, 'state', 'state cookie missing, expired or not matching');
    }
    if (params.has('error')) {
      return this.refuse(req, headers, 'provider', 'provider returned an error', {
        error: params.get('error'),
        error_description: params.get('error_description'),
      });
    }
    let oidc: client.Configuration;
    try {
      oidc = await this.discover();
    } catch (e) {
      this.cfg.logger.warn('vocauth: provider discovery failed', { err: String(e) });
      return this.fail(req, 503, 'sso_unavailable', headers);
    }
    const current = new URL(this.cfg.redirectUrl);
    current.search = new URL(req.url).search;
    let claims: client.IDToken | undefined;
    try {
      const tokens = await client.authorizationCodeGrant(oidc, current, {
        pkceCodeVerifier: st.code_verifier,
        expectedState: st.state,
        expectedNonce: st.nonce,
        idTokenExpected: true,
      });
      claims = tokens.claims();
    } catch (e) {
      const code = isExchangeError(e) ? 'exchange' : 'token';
      return this.refuse(req, headers, code, code === 'exchange' ? 'code exchange failed' : 'ID token rejected', { err: String(e) });
    }
    if (!claims) return this.refuse(req, headers, 'token', 'token response has no id_token');
    const email = admit(claims.email, claims.email_verified, this.cfg.allowedDomains, this.cfg.allowedEmails);
    if (email === null) return this.refuse(req, headers, 'domain', 'user not admitted');
    const now = this.nowSeconds();
    const session: SessionPayload = {
      sub: claims.sub,
      email,
      name: typeof claims.name === 'string' ? claims.name : '',
      iat: now,
      exp: now + this.cfg.maxAge,
    };
    headers.append('Set-Cookie', this.cookie(SESSION_COOKIE, this.keys.seal(SESSION_COOKIE, serializeSession(session)), this.cfg.maxAge));
    return redirect(303, st.return_to, headers);
  }

  /**
   * POST only (a GET logout would be cross-site requestable) and same-origin
   * only (a cross-site form POST would sign the user out). Signing out of
   * Google is separate.
   */
  private logout(req: Request): Response {
    if (req.method !== 'POST') return this.methodNotAllowed('POST');
    if (!this.sameOrigin(req)) {
      return this.refuse(req, new Headers(), 'origin', 'logout request is not same-origin', {
        origin: req.headers.get('origin'),
        sec_fetch_site: req.headers.get('sec-fetch-site'),
      });
    }
    const headers = new Headers();
    headers.append('Set-Cookie', this.clear(SESSION_COOKIE));
    return redirect(303, '/', headers);
  }

  /** Express middleware for the /auth/* routes: app.use(auth.routes()). */
  routes(): Middleware {
    return (req, res, next) => {
      const ctx: RequestContext = { ip: req.ip ?? req.socket?.remoteAddress };
      this.handle(toRequest(req), ctx)
        .then((r) => (r ? writeResponse(res, r) : next()))
        .catch(next);
    };
  }

  /** Express middleware that sets req.user or answers like challenge(). */
  require(): Middleware {
    return (req, res, next) => {
      const request = toRequest(req);
      const user = this.user(request);
      if (user) {
        req.user = user;
        next();
        return;
      }
      writeResponse(res, this.challenge(request)).catch(next);
    };
  }
}

export function vocdoniAuth(config: Config): VocdoniAuth {
  return new VocdoniAuth(config);
}
