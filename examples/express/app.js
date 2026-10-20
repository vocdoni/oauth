// SPDX-License-Identifier: AGPL-3.0-only
//
// A minimal Express tool behind Vocdoni sign-in. server.js runs it;
// node/test/express.test.ts drives it against a fake provider.

import express from 'express';
import { parseCookieKeys, vocdoniAuth } from '@vocdoni/oauth';

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

/** Allows n sign-in requests per client IP per window (fixed window). */
export function createLimiter(n = 20, windowMs = 60_000) {
  let start = 0;
  let counts = new Map();
  return (_req, ctx) => {
    const now = Date.now();
    if (now - start > windowMs) {
      start = now;
      counts = new Map();
    }
    const ip = ctx?.ip ?? 'unknown';
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
    return counts.get(ip) <= n;
  };
}

/** Builds the kit from OAUTH_* environment variables. */
export function authFromEnv(env = process.env) {
  return vocdoniAuth({
    issuer: env.OAUTH_ISSUER ?? 'https://oauth.vocdoni.org',
    clientId: env.OAUTH_CLIENT_ID,
    clientSecret: env.OAUTH_CLIENT_SECRET,
    redirectUrl: env.OAUTH_REDIRECT_URL,
    cookieKeys: parseCookieKeys(env.OAUTH_COOKIE_KEYS ?? ''),
    insecure: env.OAUTH_INSECURE === '1',
    limiter: createLimiter(),
  });
}

export function createApp(auth) {
  const app = express();
  app.use(auth.routes()); // GET /auth/login, GET /auth/callback, POST /auth/logout
  app.use(auth.require()); // everything below needs a session; sets req.user
  app.get('/', (req, res) => {
    res.type('html').send(`<!doctype html><title>Example</title>
<p>Signed in as ${escapeHtml(req.user.name)} (${escapeHtml(req.user.email)}).</p>
<form method="post" action="/auth/logout"><button>Sign out</button></form>
<p>Signing out here does not sign you out of Google.</p>
`);
  });
  app.get('/api/me', (req, res) => res.json(req.user));
  return app;
}
