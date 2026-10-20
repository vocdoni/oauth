// SPDX-License-Identifier: AGPL-3.0-only
//
// Minimal OpenID provider for tests: discovery, JWKS and a token endpoint that
// checks the client secret (basic or post), the PKCE S256 verifier and the
// redirect URI, then returns an RS256 ID token whose claims a test can rewrite.

import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

interface Issued {
  challenge: string;
  nonce: string;
  redirect: string;
}

export class FakeOP {
  readonly clientId = 'mytool';
  readonly secret = 's3cret';
  issuer = '';
  down = false;
  tokenStatus = 0;
  noIdToken = false;
  rogue = false; // sign with a key that is not in the JWKS (same kid)
  mutate: ((claims: Record<string, unknown>) => void) | undefined;
  private readonly key: KeyObject;
  private readonly codes = new Map<string, Issued>();
  private server: Server | undefined;

  constructor() {
    this.key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  }

  async start(): Promise<this> {
    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', this.issuer);
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === '/.well-known/openid-configuration') {
        if (this.down) return send(503, { error: 'down' });
        return send(200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/auth`,
          token_endpoint: `${this.issuer}/token`,
          jwks_uri: `${this.issuer}/keys`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        });
      }
      if (url.pathname === '/keys') {
        const jwk = this.key.export({ format: 'jwk' });
        return send(200, { keys: [{ kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig', kid: 'k1' }] });
      }
      if (url.pathname === '/token' && req.method === 'POST') {
        let body = '';
        req.on('data', (c: Buffer) => (body += c.toString()));
        req.on('end', () => {
          const p = new URLSearchParams(body);
          let id = p.get('client_id');
          let secret = p.get('client_secret');
          const auth = req.headers.authorization;
          if (auth?.startsWith('Basic ')) {
            const [u, s] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
            id = decodeURIComponent(u ?? '');
            secret = decodeURIComponent(s ?? '');
          }
          if (this.tokenStatus) return send(this.tokenStatus, { error: 'invalid_grant' });
          const code = p.get('code') ?? '';
          const is = this.codes.get(code);
          this.codes.delete(code);
          const challenge = createHash('sha256').update(p.get('code_verifier') ?? '').digest('base64url');
          if (id !== this.clientId || secret !== this.secret || !is || p.get('grant_type') !== 'authorization_code' ||
              challenge !== is.challenge || p.get('redirect_uri') !== is.redirect) {
            return send(400, { error: 'invalid_grant' });
          }
          const now = Math.floor(Date.now() / 1000);
          const claims: Record<string, unknown> = {
            iss: this.issuer, sub: 'CiQxMjM0', aud: this.clientId, exp: now + 600, iat: now, nonce: is.nonce,
            email: 'Alice@Vocdoni.org', email_verified: true, name: 'Alice Example',
          };
          this.mutate?.(claims);
          const resp: Record<string, unknown> = { access_token: 'at', token_type: 'Bearer', expires_in: 600 };
          if (!this.noIdToken) resp.id_token = this.sign(claims);
          send(200, resp);
        });
        return;
      }
      send(404, { error: 'not_found' });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  /** Stands in for the browser round trip through /auth; returns a code and the state. */
  authorize(authUrl: string): { code: string; state: string } {
    const q = new URL(authUrl).searchParams;
    if (q.get('client_id') !== this.clientId || q.get('response_type') !== 'code' ||
        q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge') || q.get('scope') !== 'openid email profile') {
      throw new Error(`unexpected authorization request: ${authUrl}`);
    }
    const code = randomBytes(16).toString('base64url');
    this.codes.set(code, { challenge: q.get('code_challenge')!, nonce: q.get('nonce') ?? '', redirect: q.get('redirect_uri') ?? '' });
    return { code, state: q.get('state') ?? '' };
  }

  private sign(claims: Record<string, unknown>): string {
    const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const input = `${enc({ alg: 'RS256', kid: 'k1', typ: 'JWT' })}.${enc(claims)}`;
    const key = this.rogue ? generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey : this.key;
    return `${input}.${sign('sha256', Buffer.from(input), key).toString('base64url')}`;
  }
}
