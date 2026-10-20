// SPDX-License-Identifier: AGPL-3.0-only

import { asciiLower, hasControl } from './admission.js';
import { KEY_SIZE } from './cookie.js';

export const DEFAULT_MAX_AGE = 12 * 3600; // seconds
export const MAX_MAX_AGE = 7 * 24 * 3600;
export const DEFAULT_ALLOWED_DOMAINS: readonly string[] = ['vocdoni.org'];

export interface Logger {
  warn(message: string, attrs?: Record<string, unknown>): void;
}

/** Extra request facts an adapter can pass along (the Fetch Request has no client IP). */
export interface RequestContext {
  ip?: string;
}

export interface Config {
  issuer: string; // e.g. https://oauth.vocdoni.org
  clientId: string;
  clientSecret: string;
  redirectUrl: string; // absolute URL of GET /auth/callback
  /** 32-byte AES-256 keys; [0] encrypts, any decrypts (see parseCookieKeys). */
  cookieKeys: Uint8Array[];
  /** Verified e-mails whose domain (after the last "@") equals one of these. */
  allowedDomains?: string[];
  /** Exact verified e-mails. When both lists are empty, allowedDomains = ["vocdoni.org"]. */
  allowedEmails?: string[];
  /** Absolute session lifetime in seconds (default 12 h, at most 7 days). */
  maxAge?: number;
  /** Drops the Secure cookie attribute and allows http:// URLs (localhost only). */
  insecure?: boolean;
  /** Called for GET /auth/login and /auth/callback; false answers 429. Default: allow. */
  limiter?: (req: Request, ctx?: RequestContext) => boolean;
  logger?: Logger;
  /** Clock override (tests): milliseconds since the epoch. */
  now?: () => number;
  /** Fetch override for discovery, JWKS and token requests. */
  fetch?: typeof fetch;
}

export interface ResolvedConfig extends Required<Omit<Config, 'limiter' | 'fetch'>> {
  limiter?: Config['limiter'];
  fetch?: typeof fetch;
}

function checkUrl(field: string, raw: string, insecure: boolean, errs: string[]): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    errs.push(`${field} must be an absolute URL`);
    return;
  }
  if (u.search || u.hash || !u.host) errs.push(`${field} must be an absolute URL without query or fragment`);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && insecure)) {
    errs.push(`${field} must use https (http only with insecure)`);
  }
}

export function resolveConfig(c: Config): ResolvedConfig {
  const errs: string[] = [];
  const insecure = c.insecure === true;
  checkUrl('issuer', c.issuer ?? '', insecure, errs);
  checkUrl('redirectUrl', c.redirectUrl ?? '', insecure, errs);
  if (!c.clientId || /["\\]/.test(c.clientId) || hasControl(c.clientId)) {
    errs.push('clientId is required and must not contain quotes, backslashes or control characters');
  }
  if (!c.clientSecret) errs.push('clientSecret is required');
  if (!Array.isArray(c.cookieKeys) || c.cookieKeys.length === 0) errs.push('at least one cookie key is required');
  for (const [i, k] of (c.cookieKeys ?? []).entries()) {
    if (!(k instanceof Uint8Array) || k.length !== KEY_SIZE) errs.push(`cookieKeys[${i}] must be ${KEY_SIZE} bytes`);
  }
  const maxAge = c.maxAge ?? DEFAULT_MAX_AGE;
  if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > MAX_MAX_AGE) {
    errs.push(`maxAge must be an integer between 1 and ${MAX_MAX_AGE} seconds`);
  }
  const domains: string[] = [];
  for (const d of c.allowedDomains ?? []) {
    const v = asciiLower(d.trim());
    if (!v || v.includes('@')) errs.push(`invalid allowed domain ${JSON.stringify(d)}`);
    else domains.push(v);
  }
  const emails: string[] = [];
  for (const e of c.allowedEmails ?? []) {
    const v = asciiLower(e.trim());
    const at = v.lastIndexOf('@');
    if (at <= 0 || at === v.length - 1) errs.push(`invalid allowed e-mail ${JSON.stringify(e)}`);
    else emails.push(v);
  }
  if (domains.length === 0 && emails.length === 0) domains.push(...DEFAULT_ALLOWED_DOMAINS);
  if (errs.length > 0) throw new Error(`vocauth: invalid configuration:\n- ${errs.join('\n- ')}`);
  return {
    issuer: c.issuer,
    clientId: c.clientId,
    clientSecret: c.clientSecret,
    redirectUrl: c.redirectUrl,
    cookieKeys: c.cookieKeys,
    allowedDomains: domains,
    allowedEmails: emails,
    maxAge,
    insecure,
    limiter: c.limiter,
    logger: c.logger ?? { warn: (m, a) => console.warn(m, a ?? {}) },
    now: c.now ?? Date.now,
    fetch: c.fetch,
  };
}
