// SPDX-License-Identifier: AGPL-3.0-only
//
// @vocdoni/oauth: sign in to a Node tool through oauth.vocdoni.org.
//
//   const auth = vocdoniAuth({ issuer, clientId, clientSecret, redirectUrl, cookieKeys });
//   app.use(auth.routes());   // GET /auth/login, GET /auth/callback, POST /auth/logout
//   app.use(auth.require());  // sets req.user
//
// Framework-neutral: auth.handle(request) -> Response | null, auth.user(request),
// auth.challenge(request).

export { VocdoniAuth, vocdoniAuth } from './auth.js';
export type { AuthRequest, Middleware, User } from './auth.js';
export { DEFAULT_ALLOWED_DOMAINS, DEFAULT_MAX_AGE, MAX_MAX_AGE } from './config.js';
export type { Config, Logger, RequestContext } from './config.js';
export { KEY_SIZE, SESSION_COOKIE, STATE_COOKIE, parseCookieKeys } from './cookie.js';
