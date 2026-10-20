# Tools that cannot change: oauth2-proxy

> Status: written, not deployed and untested in v1. Prefer a kit when the tool's code
> can change.

[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) can sit in front
of a tool that has no sign-in of its own and admit only `@vocdoni.org`
accounts through `oauth.vocdoni.org`.

1. Register the proxy as a client. Its callback is `/oauth2/callback` on the
   tool's public host:

   ```sh
   make add-client ID=mytool URL=https://mytool.vocdoni.io/oauth2/callback
   ```

   Set `CLIENT_MYTOOL_SECRET` on the Railway `oauth` service as printed.

2. Run oauth2-proxy next to the tool (pin the image by digest in real use):

   ```sh
   docker run --rm -p 4180:4180 quay.io/oauth2-proxy/oauth2-proxy:latest \
     --http-address=0.0.0.0:4180 \
     --provider=oidc \
     --oidc-issuer-url=https://oauth.vocdoni.org \
     --client-id=mytool \
     --client-secret="$CLIENT_MYTOOL_SECRET" \
     --redirect-url=https://mytool.vocdoni.io/oauth2/callback \
     --code-challenge-method=S256 \
     --scope="openid email profile" \
     --email-domain=vocdoni.org \
     --cookie-secret="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
     --cookie-secure=true \
     --upstream=http://tool:8080
   ```

   - `--code-challenge-method=S256` is required: the provider enforces PKCE.
   - `--email-domain=vocdoni.org` repeats the domain rule the kits apply
     (oauth2-proxy also refuses unverified e-mails by default).
   - The proxy's own cookie is its session; signing out (`/oauth2/sign_out`)
     does not sign the user out of Google.

3. Route the tool's public hostname to the proxy only, never to the tool
   directly.

Open questions before relying on it: test the flow locally with
`make dev` (issuer `http://localhost:5556`, client `dev`, redirect URI
`http://localhost:8080/auth/callback` would need a matching proxy port and
path), and decide how the proxy is rate-limited.
