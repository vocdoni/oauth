// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeOP is a minimal OpenID provider: discovery, JWKS and a token endpoint
// that checks the client secret, the PKCE S256 verifier and the redirect URI,
// then returns an RS256 ID token whose claims each test can rewrite.
type fakeOP struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string

	mu          sync.Mutex
	down        bool
	tokenStatus int                    // non-zero: token endpoint answers this status
	noIDToken   bool                   // token response without id_token
	rogue       bool                   // sign with a key that is not in the JWKS (same kid)
	mutate      func(c map[string]any) // rewrites ID token claims
	codes       map[string]issued
}

type issued struct {
	challenge, nonce, redirect string
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &fakeOP{t: t, key: key, clientID: "mytool", secret: "s3cret", codes: map[string]issued{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", op.discovery)
	mux.HandleFunc("/keys", op.keys)
	mux.HandleFunc("/token", op.token)
	op.srv = httptest.NewTLSServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

func (op *fakeOP) issuer() string { return op.srv.URL }

func (op *fakeOP) setDown(down bool) {
	op.mu.Lock()
	defer op.mu.Unlock()
	op.down = down
}

func (op *fakeOP) discovery(w http.ResponseWriter, _ *http.Request) {
	op.mu.Lock()
	down := op.down
	op.mu.Unlock()
	if down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	writeJSONValue(w, map[string]any{
		"issuer":                                op.issuer(),
		"authorization_endpoint":                op.issuer() + "/auth",
		"token_endpoint":                        op.issuer() + "/token",
		"jwks_uri":                              op.issuer() + "/keys",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (op *fakeOP) keys(w http.ResponseWriter, _ *http.Request) {
	pub := op.key.PublicKey
	writeJSONValue(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize stands in for the browser round trip through /auth: it records
// the PKCE challenge and nonce of an authorization URL and returns a code.
func (op *fakeOP) authorize(authURL string) (code, state string) {
	op.t.Helper()
	u := mustParse(op.t, authURL)
	q := u.Query()
	if q.Get("client_id") != op.clientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("scope") != "openid email profile" {
		op.t.Fatalf("unexpected authorization request: %s", authURL)
	}
	code = randomToken()
	op.mu.Lock()
	op.codes[code] = issued{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	op.mu.Unlock()
	return code, q.Get("state")
}

func (op *fakeOP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.tokenStatus != 0 {
		tokenError(w, op.tokenStatus)
		return
	}
	is, found := op.codes[r.PostForm.Get("code")]
	delete(op.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if id != op.clientID || secret != op.secret || !found ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != is.challenge ||
		r.PostForm.Get("redirect_uri") != is.redirect {
		tokenError(w, http.StatusBadRequest)
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": op.issuer(), "sub": "CiQxMjM0", "aud": op.clientID,
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nonce": is.nonce,
		"email": "Alice@Vocdoni.org", "email_verified": true, "name": "Alice Example",
	}
	if op.mutate != nil {
		op.mutate(claims)
	}
	resp := map[string]any{"access_token": "at", "token_type": "bearer", "expires_in": 600}
	if !op.noIDToken {
		resp["id_token"] = op.sign(claims)
	}
	writeJSONValue(w, resp)
}

func (op *fakeOP) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(input))
	key := op.key
	if op.rogue {
		var err error
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			op.t.Fatal(err)
		}
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		op.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func tokenError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
}

func writeJSONValue(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
