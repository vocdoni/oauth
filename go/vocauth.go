// SPDX-License-Identifier: AGPL-3.0-only

// Package vocauth signs users in to a Go web tool through the central Vocdoni
// OpenID Connect provider (https://oauth.vocdoni.org): authorization code flow
// with PKCE S256, ID token verification with go-oidc, and a stateless
// AES-256-GCM session cookie shared in format with the Node kit.
//
//	a, err := vocauth.New(vocauth.Config{...})
//	mux.Handle("/auth/", a.Routes())   // GET /auth/login, GET /auth/callback, POST /auth/logout
//	mux.Handle("/", a.Require(app))
//	user, ok := vocauth.FromContext(r.Context())
//
// Errors answer {"error":code} (an HTML page when Accept contains text/html):
// 403 state, exchange, token, domain, provider or origin (logout not
// same-origin); 503 sso_unavailable; 429 rate_limited; 401 unauthenticated;
// 405 method_not_allowed.
package vocauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// User is the signed-in user, read from the session cookie.
type User struct {
	Subject string
	Email   string // lower-cased
	Name    string
}

type ctxKey struct{}

// FromContext returns the user that Require put in the request context.
func FromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok
}

const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

var errBackoff = errors.New("vocauth: discovery is backing off after a failure")

// Auth implements the sign-in routes and the Require middleware.
type Auth struct {
	cfg    Config
	keys   *keyring
	origin string // scheme://host of RedirectURL, as a browser writes Origin

	mu       sync.Mutex // guards the fields below
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	nextTry  time.Time
	backoff  time.Duration
}

// New validates cfg. It performs no network I/O: provider metadata and keys
// are fetched on the first login, so a tool starts even when the issuer is down.
func New(cfg Config) (*Auth, error) {
	c, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	keys, err := newKeyring(c.CookieKeys)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil {
		return nil, err
	}
	return &Auth{cfg: c, keys: keys, origin: originOf(u)}, nil
}

// originOf is scheme://host lower-cased and without a default port, the form
// a browser uses in the Origin header.
func originOf(u *url.URL) string {
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (scheme == "https" && strings.HasSuffix(host, ":443")) || (scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndexByte(host, ':')]
	}
	return scheme + "://" + host
}

// sameOrigin reports whether a state-changing request comes from this tool's
// own origin: an Origin header, when present, must equal the redirect URL's
// origin; otherwise Sec-Fetch-Site must be same-origin. A request carrying
// neither header is refused (every browser sends at least one on a POST).
func (a *Auth) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == a.origin
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// discover returns the OAuth2 config and ID token verifier, fetching provider
// metadata on first use. A failure is retried on a later call after an
// exponential backoff (1 s doubling to 1 min); while backing off it fails fast.
func (a *Auth) discover() (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.oauth != nil {
		return a.oauth, a.verifier, nil
	}
	now := a.cfg.Now()
	if now.Before(a.nextTry) {
		return nil, nil, errBackoff
	}
	// go-oidc keeps this context as the configuration of the provider's
	// long-lived remote key set (JWKS refetched on unknown kid), so it must
	// not be a request context; the HTTP client carries the timeout.
	ctx := oidc.ClientContext(context.Background(), a.cfg.HTTPClient)
	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		if a.backoff == 0 {
			a.backoff = minBackoff
		} else {
			a.backoff = min(2*a.backoff, maxBackoff)
		}
		a.nextTry = now.Add(a.backoff)
		return nil, nil, err
	}
	ep := p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInHeader
	a.oauth = &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     ep,
		RedirectURL:  a.cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	// go-oidc checks exp against Now with no leeway; shifting Now back by 60 s
	// gives the specified clock skew on expiry only.
	a.verifier = p.Verifier(&oidc.Config{
		ClientID: a.cfg.ClientID,
		Now:      func() time.Time { return a.cfg.Now().Add(-clockSkew) },
	})
	return a.oauth, a.verifier, nil
}

// Routes serves GET /auth/login, GET /auth/callback and POST /auth/logout.
// Mount it with mux.Handle("/auth/", a.Routes()).
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", a.handleLogin)
	mux.HandleFunc("/auth/callback", a.handleCallback)
	mux.HandleFunc("/auth/logout", a.handleLogout)
	return mux
}

// Require passes signed-in requests to next with the User in the context.
// Otherwise GET/HEAD requests accepting text/html are redirected (302) to
// /auth/login?return_to=<path+query>, and anything else gets 401
// {"error":"unauthenticated"} with WWW-Authenticate: Cookie realm="<ClientID>".
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := a.session(w, r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
			return
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && wantsHTML(r) {
			w.Header().Set("Location", "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()))
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("WWW-Authenticate", `Cookie realm="`+a.cfg.ClientID+`"`)
		writeJSON(w, http.StatusUnauthorized, "unauthenticated")
	})
}

// session reads the session cookie; an undecodable, tampered or expired
// cookie is cleared and treated as signed out.
func (a *Auth) session(w http.ResponseWriter, r *http.Request) (User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return User{}, false
	}
	var p sessionPayload
	pt, ok := a.keys.open(SessionCookie, c.Value)
	if !ok || json.Unmarshal(pt, &p) != nil || p.Sub == "" || p.Email == "" || p.Exp <= a.cfg.Now().Unix() {
		a.clearCookie(w, SessionCookie)
		return User{}, false
	}
	return User{Subject: p.Sub, Email: p.Email, Name: p.Name}, true
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if a.cfg.Limiter != nil && !a.cfg.Limiter(r) {
		a.fail(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	oc, _, err := a.discover()
	if err != nil {
		a.cfg.Logger.Warn("vocauth: provider discovery failed", "err", err)
		a.fail(w, r, http.StatusServiceUnavailable, "sso_unavailable")
		return
	}
	st := statePayload{
		State:        randomToken(),
		Nonce:        randomToken(),
		CodeVerifier: oauth2.GenerateVerifier(), // 32 random bytes, base64url: 43 chars (RFC 7636)
		ReturnTo:     sanitizeReturnTo(r.URL.Query().Get("return_to")),
		Iat:          a.cfg.Now().Unix(),
	}
	a.setCookie(w, StateCookie, a.keys.seal(StateCookie, marshalPayload(st)), int(stateMaxAge/time.Second))
	target := oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.CodeVerifier))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if a.cfg.Limiter != nil && !a.cfg.Limiter(r) {
		a.fail(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	st, ok := a.readState(r)
	a.clearCookie(w, StateCookie) // whatever the outcome
	q := r.URL.Query()
	if !ok || q.Get("state") == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		a.refuse(w, r, "state", "state cookie missing, expired or not matching")
		return
	}
	if e := q.Get("error"); e != "" {
		a.refuse(w, r, "provider", "provider returned an error", "error", e, "error_description", q.Get("error_description"))
		return
	}
	oc, verifier, err := a.discover()
	if err != nil {
		a.cfg.Logger.Warn("vocauth: provider discovery failed", "err", err)
		a.fail(w, r, http.StatusServiceUnavailable, "sso_unavailable")
		return
	}
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.cfg.HTTPClient)
	tok, err := oc.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.CodeVerifier))
	if err != nil {
		a.refuse(w, r, "exchange", "code exchange failed", "err", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		a.refuse(w, r, "token", "token response has no id_token")
		return
	}
	idt, err := verifier.Verify(ctx, raw)
	if err != nil {
		a.refuse(w, r, "token", "ID token rejected", "err", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		a.refuse(w, r, "token", "ID token nonce mismatch")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		a.refuse(w, r, "token", "ID token claims undecodable", "err", err)
		return
	}
	email, ok := admit(claims.Email, claims.EmailVerified, a.cfg.AllowedDomains, a.cfg.AllowedEmails)
	if !ok {
		a.refuse(w, r, "domain", "user not admitted")
		return
	}
	now := a.cfg.Now()
	sp := sessionPayload{Sub: idt.Subject, Email: email, Name: claims.Name, Iat: now.Unix(), Exp: now.Add(a.cfg.MaxAge).Unix()}
	a.setCookie(w, SessionCookie, a.keys.seal(SessionCookie, marshalPayload(sp)), int(a.cfg.MaxAge/time.Second))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", st.ReturnTo)
	w.WriteHeader(http.StatusSeeOther)
}

func (a *Auth) readState(r *http.Request) (statePayload, bool) {
	var st statePayload
	c, err := r.Cookie(StateCookie)
	if err != nil {
		return st, false
	}
	pt, ok := a.keys.open(StateCookie, c.Value)
	if !ok || json.Unmarshal(pt, &st) != nil || st.State == "" || st.Nonce == "" || st.CodeVerifier == "" {
		return st, false
	}
	now := a.cfg.Now().Unix()
	if st.Iat > now+int64(clockSkew/time.Second) || now-st.Iat > int64(stateMaxAge/time.Second) {
		return st, false
	}
	st.ReturnTo = sanitizeReturnTo(st.ReturnTo)
	return st, true
}

// handleLogout clears the session: POST only (a GET logout would be
// cross-site requestable) and same-origin only (a cross-site form POST would
// sign the user out). Signing out of Google is separate.
func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !a.sameOrigin(r) {
		a.refuse(w, r, "origin", "logout request is not same-origin",
			"origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		return
	}
	a.clearCookie(w, SessionCookie)
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusSeeOther)
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is dropped only with Config.Insecure (localhost development)
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: !a.cfg.Insecure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	a.setCookie(w, name, "", -1) // Max-Age=0
}

// refuse logs the reason (never shown to the user) and answers 403.
func (a *Auth) refuse(w http.ResponseWriter, r *http.Request, code, reason string, attrs ...any) {
	a.cfg.Logger.Warn("vocauth: sign-in refused: "+reason, append([]any{"code", code}, attrs...)...)
	a.fail(w, r, http.StatusForbidden, code)
}

var messages = map[string]string{
	"state":           "The sign-in request expired or was started in another tab. Please try again.",
	"exchange":        "The sign-in could not be completed with the identity provider. Please try again.",
	"token":           "The identity provider returned an invalid sign-in token.",
	"domain":          "This account is not allowed to use this tool.",
	"provider":        "The identity provider refused the sign-in.",
	"origin":          "The sign-out request did not come from this site. Use the sign-out button.",
	"sso_unavailable": "Single sign-on is unavailable right now. Please try again later.",
	"rate_limited":    "Too many sign-in attempts. Please wait a minute and try again.",
}

// fail answers a plain HTML page to browsers and {"error":code} otherwise.
func (a *Auth) fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	if !wantsHTML(r) {
		writeJSON(w, status, code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, errorPage, html.EscapeString(messages[code]), code)
}

const errorPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body><h1>Sign-in failed</h1><p>%s</p><p>Error code: %s</p><p><a href="/auth/login">Try again</a></p></body></html>
`

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func writeJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"error\":%q}\n", code)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
}

// randomToken is 32 random bytes, base64url (43 characters): state and nonce.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
