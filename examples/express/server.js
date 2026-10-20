// SPDX-License-Identifier: AGPL-3.0-only
//
// Local development against `docker compose up` in the repository root:
//
//   (cd ../../node && npm ci && npm run build) && npm install
//   OAUTH_ISSUER=http://localhost:5556 OAUTH_CLIENT_ID=dev \
//   OAUTH_CLIENT_SECRET=dev-client-secret OAUTH_INSECURE=1 \
//   OAUTH_REDIRECT_URL=http://localhost:8080/auth/callback \
//   OAUTH_COOKIE_KEYS="$(openssl rand -base64 32)" npm start
//
// then open http://localhost:8080 and sign in as dev@vocdoni.org.

import { authFromEnv, createApp } from './app.js';

const port = Number(process.env.PORT ?? 8080);
createApp(authFromEnv()).listen(port, 'localhost', () => {
  console.log(`listening on http://localhost:${port}`);
});
