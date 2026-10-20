// SPDX-License-Identifier: AGPL-3.0-only
//
// Cookie format shared byte for byte with the Go kit (go/cookie.go):
//   value = base64url-nopad(key_id(1) || nonce(12) || AES-256-GCM ciphertext||tag)
//   AAD = cookie name, key_id = SHA-256(key)[0]
// keys[0] seals; any key whose id matches may open.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const SESSION_COOKIE = 'vocauth_session';
export const STATE_COOKIE = 'vocauth_state';
export const KEY_SIZE = 32;

const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const MAX_COOKIE_VALUE = 4096;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

// Field order is part of the cookie format (same as the Go structs).
export interface SessionPayload {
  sub: string;
  email: string;
  name: string;
  iat: number;
  exp: number;
}

export interface StatePayload {
  state: string;
  nonce: string;
  code_verifier: string;
  return_to: string;
  iat: number;
}

export function serializeSession(p: SessionPayload): string {
  return JSON.stringify({ sub: p.sub, email: p.email, name: p.name, iat: p.iat, exp: p.exp });
}

export function serializeState(p: StatePayload): string {
  return JSON.stringify({
    state: p.state,
    nonce: p.nonce,
    code_verifier: p.code_verifier,
    return_to: p.return_to,
    iat: p.iat,
  });
}

export function keyId(key: Uint8Array): number {
  return createHash('sha256').update(key).digest()[0]!;
}

export class Keyring {
  private readonly keys: Uint8Array[];
  private readonly ids: number[];

  constructor(keys: Uint8Array[]) {
    if (keys.length === 0) throw new Error('vocauth: no cookie keys');
    for (const [i, k] of keys.entries()) {
      if (k.length !== KEY_SIZE) throw new Error(`vocauth: cookieKeys[${i}] is ${k.length} bytes, want ${KEY_SIZE}`);
    }
    this.keys = keys;
    this.ids = keys.map(keyId);
  }

  /** Deterministic for a given nonce (fixtures); seal() draws a random one. */
  sealWithNonce(name: string, plaintext: string, nonce: Uint8Array): string {
    const cipher = createCipheriv('aes-256-gcm', this.keys[0]!, nonce);
    cipher.setAAD(Buffer.from(name, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return Buffer.concat([Buffer.from([this.ids[0]!]), nonce, ct, cipher.getAuthTag()]).toString('base64url');
  }

  seal(name: string, plaintext: string): string {
    return this.sealWithNonce(name, plaintext, randomBytes(NONCE_SIZE));
  }

  open(name: string, value: string): string | null {
    if (value.length === 0 || value.length > MAX_COOKIE_VALUE || !BASE64URL_RE.test(value)) return null;
    const raw = Buffer.from(value, 'base64url');
    if (raw.length < 1 + NONCE_SIZE + TAG_SIZE) return null;
    const id = raw[0];
    const nonce = raw.subarray(1, 1 + NONCE_SIZE);
    const ct = raw.subarray(1 + NONCE_SIZE, raw.length - TAG_SIZE);
    const tag = raw.subarray(raw.length - TAG_SIZE);
    for (const [i, key] of this.keys.entries()) {
      if (this.ids[i] !== id) continue;
      try {
        const d = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_SIZE });
        d.setAAD(Buffer.from(name, 'utf8'));
        d.setAuthTag(tag);
        return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
      } catch {
        // wrong key or tampered value: try the next key with the same id
      }
    }
    return null;
  }
}

/** 32 random bytes, base64url (state, nonce and PKCE code_verifier). */
export function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

export interface CookieOptions {
  maxAge: number; // seconds; 0 clears
  secure: boolean;
}

/** Same attribute order as Go's http.Cookie.String(). */
export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  return `${name}=${value}; Path=/; Max-Age=${o.maxAge}; HttpOnly${o.secure ? '; Secure' : ''}; SameSite=Lax`;
}

/** First value of the named cookie in a Cookie header, if any. */
export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

/**
 * Parses a comma-separated list of base64 (standard or URL alphabet, padding
 * optional) 32-byte keys, e.g. `openssl rand -base64 32`. The first key seals.
 */
export function parseCookieKeys(s: string): Uint8Array[] {
  return s.split(',').map((part, i) => {
    const t = part.trim().replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
    const k = BASE64URL_RE.test(t) ? Buffer.from(t, 'base64url') : Buffer.alloc(0);
    if (k.length !== KEY_SIZE) throw new Error(`vocauth: cookie key ${i} is not base64 of ${KEY_SIZE} bytes`);
    return new Uint8Array(k);
  });
}
