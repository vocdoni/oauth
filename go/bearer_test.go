// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bearerHarness runs a Bearer against a fakeOP behind Require, where the app
// echoes the user as JSON. Tests advance the clock by moving offset.
type bearerHarness struct {
	t      *testing.T
	op     *fakeOP
	b      *Bearer
	h      http.Handler
	offset time.Duration
}

func newBearerHarness(t *testing.T, mod func(*BearerConfig)) *bearerHarness {
	t.Helper()
	return newBearerHarnessFor(t, newFakeOP(t), mod)
}

func newBearerHarnessFor(t *testing.T, op *fakeOP, mod func(*BearerConfig)) *bearerHarness {
	t.Helper()
	h := &bearerHarness{t: t, op: op}
	cfg := BearerConfig{
		Issuer:     op.issuer(),
		Audiences:  []string{op.clientID},
		HTTPClient: op.srv.Client(),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        func() time.Time { return time.Now().Add(h.offset) },
	}
	if mod != nil {
		mod(&cfg)
	}
	b, err := NewBearer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.b = b
	h.h = b.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := FromContext(r.Context())
		if !ok {
			t.Error("Require passed a request without a user")
		}
		_ = json.NewEncoder(w).Encode(u)
	}))
	return h
}

// get sends a request with the given Authorization header (none when empty).
func (h *bearerHarness) get(authorization string) *http.Response {
	h.t.Helper()
	r := httptest.NewRequest("GET", "/api/items", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, r)
	return rec.Result()
}

// bearer sends a request carrying the access token minted with mutate.
func (h *bearerHarness) bearer(mutate func(c map[string]any)) *http.Response {
	h.t.Helper()
	return h.get("Bearer " + h.op.accessToken(mutate))
}

// tamperSignature flips a bit of the JWT signature.
func tamperSignature(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func assertRefused(t *testing.T, res *http.Response, status int, code string) {
	t.Helper()
	if res.StatusCode != status || errorCode(t, res) != code {
		t.Fatalf("status %d, want %d %s", res.StatusCode, status, code)
	}
}

func TestBearerValidToken(t *testing.T) {
	h := newBearerHarness(t, nil)
	res := h.bearer(nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var u User
	if err := json.NewDecoder(res.Body).Decode(&u); err != nil {
		t.Fatal(err)
	}
	want := User{Subject: "CiQxMjM0", Email: "alice@vocdoni.org", Name: "Alice Example"}
	if u != want {
		t.Fatalf("user = %+v, want %+v", u, want)
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	h := newBearerHarness(t, nil)
	tok := h.op.accessToken(nil)
	for _, v := range []string{"bearer " + tok, "BEARER " + tok} {
		if res := h.get(v); res.StatusCode != http.StatusOK {
			t.Fatalf("%q: status %d", v[:6], res.StatusCode)
		}
	}
}

func TestBearerRejectsInvalidTokens(t *testing.T) {
	h := newBearerHarness(t, nil)
	cases := map[string]func(c map[string]any){
		"wrong audience": func(c map[string]any) { c["aud"] = "stranger" },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() },
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"no subject":     func(c map[string]any) { delete(c, "sub") },
	}
	for name, mutate := range cases {
		if res := h.bearer(mutate); res.StatusCode != http.StatusUnauthorized || errorCode(t, res) != "invalid_token" {
			t.Errorf("%s: status %d", name, res.StatusCode)
		}
	}
	if res := h.get("Bearer " + tamperSignature(t, h.op.accessToken(nil))); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad signature: status %d", res.StatusCode)
	}
	if res := h.get("Bearer not-a-jwt"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("malformed: status %d", res.StatusCode)
	}
}

func TestBearerAudienceList(t *testing.T) {
	h := newBearerHarness(t, func(c *BearerConfig) { c.Audiences = []string{"mytool", "auditore-mcp"} })
	if res := h.bearer(func(c map[string]any) { c["aud"] = "auditore-mcp" }); res.StatusCode != http.StatusOK {
		t.Fatalf("second audience: status %d", res.StatusCode)
	}
	if res := h.bearer(func(c map[string]any) { c["aud"] = []string{"other", "mytool"} }); res.StatusCode != http.StatusOK {
		t.Fatalf("audience array: status %d", res.StatusCode)
	}
}

func TestBearerAllowedEmailsNarrow(t *testing.T) {
	h := newBearerHarness(t, func(c *BearerConfig) { c.AllowedEmails = []string{"Guest@Example.com"} })
	assertRefused(t, h.bearer(nil), http.StatusForbidden, "forbidden")
	if res := h.bearer(func(c map[string]any) { c["email"] = "GUEST@example.com" }); res.StatusCode != http.StatusOK {
		t.Fatalf("allowed guest: status %d", res.StatusCode)
	}
}

// A valid token of a user who may not sign in gets 403, so MCP clients do not
// loop re-authorizing; a missing e-mail asks for the email scope instead.
func TestBearerForbidden(t *testing.T) {
	const meta = "https://api.vocdoni.io/.well-known/oauth-protected-resource"
	cases := []struct {
		name, metadataURL, want string
		mutate                  func(c map[string]any)
	}{
		{"not verified", "", `Bearer realm="vocdoni", error="insufficient_scope"`,
			func(c map[string]any) { c["email_verified"] = false }},
		{"other domain", meta, `Bearer realm="vocdoni", error="insufficient_scope", resource_metadata="` + meta + `"`,
			func(c map[string]any) { c["email"] = "bob@example.com" }},
		{"no email", "", `Bearer realm="vocdoni", error="insufficient_scope", scope="openid email"`,
			func(c map[string]any) { delete(c, "email") }},
	}
	for _, c := range cases {
		h := newBearerHarness(t, func(cfg *BearerConfig) { cfg.ResourceMetadataURL = c.metadataURL })
		res := h.bearer(c.mutate)
		assertRefused(t, res, http.StatusForbidden, "forbidden")
		if got := res.Header.Get("WWW-Authenticate"); got != c.want {
			t.Errorf("%s: WWW-Authenticate %q, want %q", c.name, got, c.want)
		}
	}
}

// rawJWT assembles header, claims and signature without signing, so tests can
// present tokens the provider never issued.
func rawJWT(t *testing.T, header string, claims map[string]any, sig []byte) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(body) + "." + enc(sig)
}

// Algorithm confusion: an unsigned token and an HMAC token keyed with the
// provider's public key must both be refused.
func TestBearerRejectsAlgorithmConfusion(t *testing.T) {
	h := newBearerHarness(t, nil)
	claims := h.op.accessClaims(nil)
	none := rawJWT(t, `{"alg":"none","typ":"JWT"}`, claims, nil)
	mac := hmac.New(sha256.New, h.op.key.N.Bytes())
	signingInput := rawJWT(t, `{"alg":"HS256","kid":"k1","typ":"JWT"}`, claims, nil)
	signingInput = signingInput[:strings.LastIndexByte(signingInput, '.')]
	mac.Write([]byte(signingInput))
	hs := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	assertRefused(t, h.get("Bearer "+none), http.StatusUnauthorized, "invalid_token")
	assertRefused(t, h.get("Bearer "+hs), http.StatusUnauthorized, "invalid_token")
}

// Forged tokens cost at most one JWKS request per refetchEvery.
func TestBearerRefetchIsThrottled(t *testing.T) {
	h := newBearerHarness(t, nil)
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("warm-up: status %d", res.StatusCode)
	}
	if hits := h.op.jwksHits(); hits != 1 {
		t.Fatalf("JWKS hits after warm-up: %d", hits)
	}
	for range 5 {
		assertRefused(t, h.get("Bearer "+tamperSignature(t, h.op.accessToken(nil))), http.StatusUnauthorized, "invalid_token")
		assertRefused(t, h.get("Bearer "+h.op.signKID(h.op.accessClaims(nil), "k2")), http.StatusUnauthorized, "invalid_token")
	}
	if hits := h.op.jwksHits(); hits != 1 {
		t.Fatalf("JWKS hits for forged tokens: %d, want 1", hits)
	}
	h.offset += refetchEvery + time.Second
	assertRefused(t, h.get("Bearer "+h.op.signKID(h.op.accessClaims(nil), "k2")), http.StatusUnauthorized, "invalid_token")
	if hits := h.op.jwksHits(); hits != 2 {
		t.Fatalf("JWKS hits after the interval: %d, want 2", hits)
	}
}

// After a key rotation a token with the new kid is accepted once the refetch
// interval has passed, while a token with a cached kid never causes a fetch.
func TestBearerKeyRotation(t *testing.T) {
	h := newBearerHarness(t, nil)
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("warm-up: status %d", res.StatusCode)
	}
	forged := tamperSignature(t, h.op.accessToken(nil))
	h.op.rotate("k2")
	h.offset += refetchEvery + time.Second
	assertRefused(t, h.get("Bearer "+forged), http.StatusUnauthorized, "invalid_token")
	if hits := h.op.jwksHits(); hits != 1 {
		t.Fatalf("JWKS hits for a forged cached-kid token: %d, want 1", hits)
	}
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("new kid after rotation: status %d", res.StatusCode)
	}
	if hits := h.op.jwksHits(); hits != 2 {
		t.Fatalf("JWKS hits after rotation: %d, want 2", hits)
	}
}

// During an outage the provider is contacted once per interval and the
// warning is logged once per interval, not once per request.
func TestBearerOutageIsThrottled(t *testing.T) {
	op := newFakeOP(t)
	op.setKeysDown(true)
	var logs bytes.Buffer
	h := newBearerHarnessFor(t, op, func(c *BearerConfig) {
		c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	for range 5 {
		assertRefused(t, h.bearer(nil), http.StatusServiceUnavailable, "sso_unavailable")
	}
	if hits := op.jwksHits(); hits != 1 {
		t.Fatalf("JWKS hits during outage: %d, want 1", hits)
	}
	if n := strings.Count(logs.String(), "bearer token not verified"); n != 1 {
		t.Fatalf("warnings logged: %d, want 1", n)
	}
	op.setKeysDown(false)
	assertRefused(t, h.bearer(nil), http.StatusServiceUnavailable, "sso_unavailable")
	h.offset += refetchEvery + time.Second
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("after recovery: status %d", res.StatusCode)
	}
}

func TestBearerMissingOrNonBearerHeader(t *testing.T) {
	h := newBearerHarness(t, nil)
	for _, v := range []string{"", "Basic dXNlcjpwYXNz", "Bearer ", "Bearer"} {
		res := h.get(v)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%q: status %d", v, res.StatusCode)
		}
		if code := errorCode(t, res); code != "unauthenticated" {
			t.Fatalf("%q: error %q, want unauthenticated", v, code)
		}
		if got := res.Header.Get("WWW-Authenticate"); got != `Bearer realm="vocdoni"` {
			t.Fatalf("%q: WWW-Authenticate %q", v, got)
		}
	}
}

func TestBearerWWWAuthenticate(t *testing.T) {
	const meta = "https://api.vocdoni.io/.well-known/oauth-protected-resource"
	bad := "Bearer " + "x.y.z"
	cases := []struct {
		name, metadataURL, authorization, want string
	}{
		{"missing, no metadata", "", "", `Bearer realm="vocdoni"`},
		{"missing, metadata", meta, "", `Bearer realm="vocdoni", resource_metadata="` + meta + `"`},
		{"invalid, no metadata", "", bad, `Bearer realm="vocdoni", error="invalid_token"`},
		{"invalid, metadata", meta, bad, `Bearer realm="vocdoni", error="invalid_token", resource_metadata="` + meta + `"`},
	}
	for _, c := range cases {
		h := newBearerHarness(t, func(cfg *BearerConfig) { cfg.ResourceMetadataURL = c.metadataURL })
		if got := h.get(c.authorization).Header.Get("WWW-Authenticate"); got != c.want {
			t.Errorf("%s: WWW-Authenticate %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBearerProviderDownThenRecovers(t *testing.T) {
	op := newFakeOP(t)
	op.setDown(true)
	h := newBearerHarnessFor(t, op, nil)
	assertRefused(t, h.bearer(nil), http.StatusServiceUnavailable, "sso_unavailable")
	op.setDown(false)
	// Still inside the one-second backoff: refused without contacting the provider.
	assertRefused(t, h.bearer(nil), http.StatusServiceUnavailable, "sso_unavailable")
	h.offset += 2 * time.Second
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("after recovery: status %d", res.StatusCode)
	}
}

func TestBearerKeysDownIsUnavailable(t *testing.T) {
	op := newFakeOP(t)
	op.setKeysDown(true)
	h := newBearerHarnessFor(t, op, nil)
	assertRefused(t, h.bearer(nil), http.StatusServiceUnavailable, "sso_unavailable")
	op.setKeysDown(false)
	h.offset += refetchEvery + time.Second
	if res := h.bearer(nil); res.StatusCode != http.StatusOK {
		t.Fatalf("after keys recover: status %d", res.StatusCode)
	}
}

func TestBearerVerifyErrors(t *testing.T) {
	op := newFakeOP(t)
	op.setDown(true)
	h := newBearerHarnessFor(t, op, nil)
	if _, err := h.b.Verify(t.Context(), op.accessToken(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("provider down: %v", err)
	}
	op.setDown(false)
	h.offset += 2 * time.Second
	if _, err := h.b.Verify(t.Context(), tamperSignature(t, op.accessToken(nil))); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("bad signature: %v", err)
	}
	if _, err := h.b.Verify(t.Context(), op.accessToken(nil)); err != nil {
		t.Fatalf("valid token: %v", err)
	}
}

func TestNewBearerValidation(t *testing.T) {
	good := BearerConfig{Issuer: "https://oauth.vocdoni.org", Audiences: []string{"auditore-mcp"}}
	b, err := NewBearer(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.cfg.AllowedDomains) != 1 || b.cfg.AllowedDomains[0] != "vocdoni.org" {
		t.Fatalf("default domains not applied: %+v", b.cfg.AllowedDomains)
	}
	bad := []func(*BearerConfig){
		func(c *BearerConfig) { c.Audiences = nil },
		func(c *BearerConfig) { c.Audiences = []string{"  "} },
		func(c *BearerConfig) { c.Issuer = "" },
		func(c *BearerConfig) { c.Issuer = "http://oauth.vocdoni.org" },
		func(c *BearerConfig) { c.ResourceMetadataURL = "http://api.example/meta" },
		func(c *BearerConfig) {
			c.Insecure = true
			c.ResourceMetadataURL = `https://api.example/"x`
		},
		func(c *BearerConfig) { c.AllowedDomains = []string{"@vocdoni.org"} },
	}
	for i, mod := range bad {
		c := good
		mod(&c)
		if _, err := NewBearer(c); err == nil {
			t.Errorf("case %d: NewBearer accepted an invalid config", i)
		}
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	h := ProtectedResourceMetadata("https://api.vocdoni.io", "https://oauth.vocdoni.org", []string{"openid", "email"})
	res := serve(h, "GET")
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("GET: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var got map[string]any
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["resource"] != "https://api.vocdoni.io" ||
		strings.Join(toStrings(got["authorization_servers"]), ",") != "https://oauth.vocdoni.org" ||
		strings.Join(toStrings(got["bearer_methods_supported"]), ",") != "header" ||
		strings.Join(toStrings(got["scopes_supported"]), ",") != "openid,email" {
		t.Fatalf("metadata: %v", got)
	}
	if res := serve(ProtectedResourceMetadata("https://api.vocdoni.io", "https://oauth.vocdoni.org", nil), "GET"); strings.Contains(readBody(t, res), "scopes_supported") {
		t.Fatal("scopes_supported should be omitted when no scopes are given")
	}
	for _, method := range []string{"POST", "HEAD", "DELETE"} {
		if res := serve(h, method); res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "GET" {
			t.Fatalf("%s: %d", method, res.StatusCode)
		}
	}
}

func serve(h http.Handler, method string) *http.Response {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/.well-known/oauth-protected-resource", nil))
	return rec.Result()
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
