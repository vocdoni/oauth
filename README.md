# Vocdoni OAuth

Vocdoni staff sign in to every internal web tool with their Google
`@vocdoni.org` account. Google is configured once, in one central OpenID
Connect provider at `https://oauth.vocdoni.org`, and each tool adds a few
lines with the Go or the Node/TypeScript kit.

- **Service**: [Dex](https://dexidp.io) v2.46.0 with a Google connector
  restricted to `vocdoni.org`, published as `ghcr.io/vocdoni/oauth` and run on
  Railway.
- **Go kit**: module `github.com/vocdoni/oauth/go`, package `vocauth` ([go/](go/)).
- **Node kit**: `@vocdoni/oauth`, TypeScript ESM on `openid-client` v6, with an
  Express adapter ([node/](node/)).
- **Examples**: [examples/go](examples/go) and [examples/express](examples/express).
- Tools that cannot change: an oauth2-proxy recipe in [docs/proxy.md](docs/proxy.md)
  (written, untested).

How it works: each tool runs the standard authorization code flow with PKCE
against `oauth.vocdoni.org`, which sends the user to Google. Tools live on
different domains, so each keeps its own session cookie. Dex keeps no session
of its own; "sign in once" comes from Google: while the browser's Google
session is alive, the next tool signs in with at most an account chooser.
There is no central logout: signing out of a tool ends that tool's session
only, and the Google session is not ours to end.

## Add a tool

1. Register the client (one per tool, exact production callback URL):

   ```sh
   make add-client ID=mytool URL=https://mytool.vocdoni.io/auth/callback NAME="My tool"
   ```

   This appends the client to [config.yaml](config.yaml) and prints the
   Railway variable to set: `CLIENT_MYTOOL_SECRET` (the id upper-cased, every
   character outside `[A-Z0-9]` replaced by `_`). Generate the secret with
   `openssl rand -hex 32`, set it on Railway, then open a pull request with the
   config change. Dex refuses to start while a client's secret variable is
   unset, so set the variable before merging. After the merge, CI promotes
   `latest`; Railway does not follow a moving tag, so redeploy the service
   (Railway, Deployments, Redeploy, or the configured image auto-update
   window) for Dex to pick up the new client.
2. Give the tool `OAUTH_CLIENT_ID=mytool`, `OAUTH_CLIENT_SECRET=<the secret>`,
   `OAUTH_REDIRECT_URL=https://mytool.vocdoni.io/auth/callback` and cookie
   keys (`openssl rand -base64 32`; keep a comma-separated list to rotate:
   the first key encrypts, any key decrypts).
3. Integrate a kit.

Go (`go get github.com/vocdoni/oauth/go@v0.1.0`):

```go
keys, err := vocauth.ParseCookieKeys(os.Getenv("OAUTH_COOKIE_KEYS"))
a, err := vocauth.New(vocauth.Config{
    Issuer:       "https://oauth.vocdoni.org",
    ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
    ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
    RedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
    CookieKeys:   keys,
    // optional: AllowedDomains (default ["vocdoni.org"]), AllowedEmails,
    // MaxAge (default 12h, at most 7 days), Insecure (localhost), Limiter
})
mux.Handle("/auth/", a.Routes())             // GET /auth/login, GET /auth/callback, POST /auth/logout
mux.Handle("/", a.Require(app))
user, ok := vocauth.FromContext(r.Context()) // Subject, Email, Name
```

Node (no token needed):

```sh
npm i https://github.com/vocdoni/oauth/releases/download/node/v0.1.0/vocdoni-oauth-0.1.0.tgz
```

```js
import { parseCookieKeys, vocdoniAuth } from '@vocdoni/oauth';

const auth = vocdoniAuth({
  issuer: 'https://oauth.vocdoni.org',
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  redirectUrl: process.env.OAUTH_REDIRECT_URL,
  cookieKeys: parseCookieKeys(process.env.OAUTH_COOKIE_KEYS),
});
app.use(auth.routes());  // Express
app.use(auth.require()); // sets req.user = { subject, email, name }
// Other frameworks: await auth.handle(request) (Response | null),
// auth.user(request), auth.challenge(request).
```

Kit behaviour (identical in both kits):

- Admission: the ID token's `email` must be present and `email_verified`
  true; the lower-cased e-mail must be in `AllowedEmails`, or its domain
  (after the last `@`) in `AllowedDomains`. The default `["vocdoni.org"]`
  applies only when both lists are empty, so `AllowedEmails` alone narrows a
  tool to those people.
- Sessions are stateless AES-256-GCM cookies (`vocauth_session`, host-only,
  HttpOnly, Secure, SameSite Lax) with an absolute expiry (default 12 h).
  Revoking access: suspended Workspace accounts cannot sign in again; existing
  sessions end at their expiry or when the tool rotates its cookie keys.
- Unauthenticated browser `GET`s are redirected to `/auth/login`; other
  requests get `401 {"error":"unauthenticated"}`.
- `/auth/logout` is `POST` only (a form button) and same-origin only: the
  kits require `Origin` equal to the tool's origin or `Sec-Fetch-Site:
  same-origin` (browsers send them on form posts) and answer 403
  `{"error":"origin"}` otherwise, so a cross-site page cannot sign users out.
  It ends the tool session; it does not sign the user out of Google.
- Rate limiting: put a limiter in front of `/auth/login` and `/auth/callback`
  through the `Limiter` hook (see the examples); the kits allow everything by
  default.
- If the provider is down, the tool still starts; sign-in answers
  `503 {"error":"sso_unavailable"}` and is retried with backoff.

## Google setup (once)

1. Google Cloud console, in a project that belongs to the vocdoni.org
   organisation: OAuth consent screen **Internal**; OAuth client type **Web
   application**; authorised redirect URI `https://oauth.vocdoni.org/callback`.
2. Store the client id and secret only in the Railway variables
   `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (see Operations), never in
   the repository.
3. DNS: a CNAME for `oauth.vocdoni.org` pointing to the Railway service
   domain, plus the TXT verification record Railway asks for.

The Internal consent screen admits only organisation accounts and needs no
Google app verification. Files matching `*-secret*.txt`, `*-token.txt` and
`*-api-key.txt` are ignored by git and excluded from the image build context.

## Local development

```sh
make dev PASSWORD=<choose one>
```

runs the same image (with [dev/config.yaml](dev/config.yaml)) on
`http://localhost:5556` with a password database instead of Google: user
`dev@vocdoni.org` with that password, client `dev` with secret
`dev-client-secret` and redirect URI `http://localhost:8080/auth/callback`.
The header comment of each example lists the environment for that setup
(`OAUTH_INSECURE=1` allows plain-http localhost). `make dev-down` stops it.

Other targets: `make image`, `make smoke` (build and run the container smoke
test), `make test` (both kits and the Go example).

## Operations (Railway)

The Railway project holds one service, `oauth`, with source image
`ghcr.io/vocdoni/oauth:latest` (moved only after the image passed the smoke
test natively on amd64 and arm64), served at `https://oauth.vocdoni.org`.

| Variable | Value |
| --- | --- |
| `PORT` | `5556` |
| `ISSUER` | `https://oauth.vocdoni.org` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | from the Google OAuth client |
| `CLIENT_<ID>_SECRET` | one per client, e.g. `CLIENT_FOLIO_SECRET` |
| `RAILWAY_RUN_UID` | `0` |
| `DEX_CONFIG_DISALLOW_UNKNOWN_FIELDS` | `true` |

- Volume: 1 GB mounted at `/data` (SQLite `/data/dex.db`: signing keys and
  in-flight auth requests). Railway mounts volumes root-owned and the Dex
  image runs as uid 1001, hence `RAILWAY_RUN_UID=0` (Dex runs as root inside
  its single-purpose container; revisit if upstream ships a
  privilege-dropping entrypoint).
- Health check path `/healthz`; custom domain `oauth.vocdoni.org`.
- Volume backups enabled. Take a backup before any Dex minor upgrade: SQLite
  migrations are forward-only.
- Deploys: Railway stops the old container before starting the new one for
  services with a volume, so one Dex process opens the database; a deploy
  costs seconds of sign-in downtime, and tool sessions are unaffected. A fresh
  volume regenerates signing keys and only invalidates ID tokens in flight.
- Deploying a new image: after CI promotes `latest`, redeploy the service in
  Railway (or enable Settings, Source, Configure Auto Updates with a
  maintenance window; read the Dex upgrade rule below before enabling).
- Logs: JSON on stdout, level info, without e-mail and user names.
- Dex upgrade: Dependabot proposes patch releases only; minor/major bumps are
  manual: bump the tag and digest in the Dockerfile in a pull request; CI runs
  the smoke test; take a volume backup; merge, then redeploy the service (or
  wait for the image auto-update window if enabled). Rollback: redeploy the
  previous image digest.

Releases: the image is published from `main` (and `vX.Y.Z` tags). The Go kit
is released by pushing a tag `go/vX.Y.Z`; the Node kit by pushing
`node/vX.Y.Z` matching `node/package.json`, which attaches the `npm pack`
tarball to a GitHub release. Both kits stay 0.x until Folio and one more tool
run them.

## Security notes

- Trust boundary: tools trust only ID tokens for their own client id signed
  by the central JWKS; the central service trusts only Google for
  `hd=vocdoni.org`.
- Policy: authorization code flow only, PKCE S256 enforced by Dex, no
  implicit, password, device or refresh grants requested; `/token` requires
  the client secret. Every unknown configuration key stops the container, in
  CI and in production (`DEX_CONFIG_DISALLOW_UNKNOWN_FIELDS=true`).
- Secrets live only in Railway variables, never in the repository, the image
  or logs. The kits log refusal reasons and provider error strings server
  side and never reflect them to the browser.
- Access is domain-wide; narrow a tool with `AllowedEmails`. Google Groups
  are not supported (they need a Workspace service account).
- Availability: if the provider is down nobody signs in through SSO; existing
  tool sessions continue.

## License

[AGPL-3.0-only](LICENSE).
