// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// harness wires an Auth against a fakeOP behind a mux like a real tool:
// /auth/ -> Routes, / -> Require(app), where app echoes the user as JSON.
type harness struct {
	t   *testing.T
	op  *fakeOP
	a   *Auth
	mux *http.ServeMux

	mu     sync.Mutex
	offset time.Duration
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, op: newFakeOP(t)}
	cfg := Config{
		Issuer:       h.op.issuer(),
		ClientID:     "mytool",
		ClientSecret: "s3cret",
		RedirectURL:  "https://mytool.example/auth/callback",
		CookieKeys:   [][]byte{seqKey(7)},
		HTTPClient:   h.op.srv.Client(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:          h.now,
	}
	if mod != nil {
		mod(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.a = a
	h.mux = http.NewServeMux()
	h.mux.Handle("/auth/", a.Routes())
	h.mux.Handle("/", a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := FromContext(r.Context())
		if !ok {
			t.Error("Require passed a request without a user")
		}
		_ = json.NewEncoder(w).Encode(u)
	})))
	return h
}

func (h *harness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Now().Add(h.offset)
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.offset += d
}

func (h *harness) do(method, target, accept string, cookies ...*http.Cookie) *http.Response {
	h.t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec.Result()
}

// login starts a sign-in and returns the authorization URL and state cookie.
func (h *harness) login(returnTo string) (string, *http.Cookie) {
	h.t.Helper()
	res := h.do("GET", "/auth/login?return_to="+url.QueryEscape(returnTo), "text/html")
	if res.StatusCode != http.StatusFound {
		h.t.Fatalf("login: status %d", res.StatusCode)
	}
	return res.Header.Get("Location"), cookieNamed(res, StateCookie)
}

// signIn runs the whole flow and returns the callback response.
func (h *harness) signIn(returnTo string) *http.Response {
	h.t.Helper()
	authURL, state := h.login(returnTo)
	code, st := h.op.authorize(authURL)
	return h.do("GET", "/auth/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(st), "", state)
}

// post sends a POST with extra headers and no Accept (JSON answers).
func (h *harness) post(target string, headers map[string]string, cookies ...*http.Cookie) *http.Response {
	h.t.Helper()
	r := httptest.NewRequest("POST", target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec.Result()
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func errorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	var body struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return body.Error
}

func TestHappyPath(t *testing.T) {
	h := newHarness(t, nil)
	authURL, state := h.login("/docs?x=1")
	if !strings.HasPrefix(authURL, h.op.issuer()+"/auth?") {
		t.Fatalf("login redirects to %s", authURL)
	}
	if state == nil || !state.HttpOnly || !state.Secure || state.SameSite != http.SameSiteLaxMode || state.Path != "/" || state.MaxAge != 600 || state.Domain != "" {
		t.Fatalf("state cookie attributes: %+v", state)
	}
	q := mustParse(t, authURL).Query()
	if len(q.Get("state")) != 43 || len(q.Get("nonce")) != 43 || q.Get("redirect_uri") != "https://mytool.example/auth/callback" {
		t.Fatalf("state/nonce must be 32 random bytes base64url: %v", q)
	}
	code, st := h.op.authorize(authURL)
	res := h.do("GET", "/auth/callback?code="+code+"&state="+st, "text/html", state)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/docs?x=1" {
		t.Fatalf("callback: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if c := cookieNamed(res, StateCookie); c == nil || c.MaxAge >= 0 {
		t.Fatalf("state cookie not cleared: %+v", c)
	}
	session := cookieNamed(res, SessionCookie)
	if session == nil || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.MaxAge != 12*3600 {
		t.Fatalf("session cookie attributes: %+v", session)
	}
	res = h.do("GET", "/anything", "application/json", session)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("signed-in request: %d", res.StatusCode)
	}
	var u User
	_ = json.NewDecoder(res.Body).Decode(&u)
	if u != (User{Subject: "CiQxMjM0", Email: "alice@vocdoni.org", Name: "Alice Example"}) {
		t.Fatalf("user = %+v", u)
	}
}

func TestRequireUnauthenticated(t *testing.T) {
	h := newHarness(t, nil)
	res := h.do("GET", "/docs?a=1&b=%2F", "text/html,application/xhtml+xml")
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/auth/login?return_to=%2Fdocs%3Fa%3D1%26b%3D%252F" {
		t.Fatalf("browser GET: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := h.do("HEAD", "/docs", "text/html"); res.StatusCode != http.StatusFound {
		t.Fatalf("browser HEAD: %d", res.StatusCode)
	}
	for _, c := range []struct{ method, accept string }{{"GET", "application/json"}, {"GET", ""}, {"POST", "text/html"}} {
		res := h.do(c.method, "/api/x", c.accept)
		if res.StatusCode != http.StatusUnauthorized || res.Header.Get("WWW-Authenticate") != `Cookie realm="mytool"` || errorCode(t, res) != "unauthenticated" {
			t.Fatalf("%s %q: %d %q", c.method, c.accept, res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
	}
}

func TestSessionCookieTamperedExpiredOrUnknownKey(t *testing.T) {
	h := newHarness(t, nil)
	session := cookieNamed(h.signIn("/"), SessionCookie)
	b := []byte(session.Value)
	if b[20] == 'A' {
		b[20] = 'B'
	} else {
		b[20] = 'A'
	}
	check := func(name string, c *http.Cookie) {
		t.Helper()
		res := h.do("GET", "/x", "application/json", c)
		cleared := cookieNamed(res, SessionCookie)
		if res.StatusCode != http.StatusUnauthorized || cleared == nil || cleared.MaxAge >= 0 {
			t.Fatalf("%s: status %d, cleared %+v", name, res.StatusCode, cleared)
		}
	}
	check("tampered", &http.Cookie{Name: SessionCookie, Value: string(b)})
	check("garbage", &http.Cookie{Name: SessionCookie, Value: "%%%"})

	other := newHarness(t, func(c *Config) { c.CookieKeys = [][]byte{seqKey(9)} })
	res := other.do("GET", "/x", "application/json", session)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown key: %d", res.StatusCode)
	}

	h.advance(12*time.Hour + time.Second)
	check("expired", session)
}

func TestKeyRotation(t *testing.T) {
	op := newHarness(t, nil)
	session := cookieNamed(op.signIn("/"), SessionCookie)
	rotated := newHarness(t, func(c *Config) { c.CookieKeys = [][]byte{seqKey(8), seqKey(7)} })
	if res := rotated.do("GET", "/x", "", session); res.StatusCode != http.StatusOK {
		t.Fatalf("session sealed with the old key rejected after rotation: %d", res.StatusCode)
	}
	fresh := cookieNamed(rotated.signIn("/"), SessionCookie)
	if res := op.do("GET", "/x", "", fresh); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("new sessions must be sealed with keys[0]: %d", res.StatusCode)
	}
}

func TestCallbackRefusals(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(op *fakeOP)
		status int
		code   string
	}{
		{"wrong audience", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["aud"] = "othertool" } }, 403, "token"},
		{"wrong issuer", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["iss"] = "https://evil.example" } }, 403, "token"},
		{"wrong nonce", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["nonce"] = "other" } }, 403, "token"},
		{"missing nonce", func(op *fakeOP) { op.mutate = func(c map[string]any) { delete(c, "nonce") } }, 403, "token"},
		{"expired beyond skew", func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["exp"] = time.Now().Add(-90 * time.Second).Unix() }
		}, 403, "token"},
		{"expired within skew", func(op *fakeOP) {
			op.mutate = func(c map[string]any) { c["exp"] = time.Now().Add(-30 * time.Second).Unix() }
		}, 303, ""},
		{"signed by another key", func(op *fakeOP) { op.rogue = true }, 403, "token"},
		{"no id_token", func(op *fakeOP) { op.noIDToken = true }, 403, "token"},
		{"email not verified", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["email_verified"] = false } }, 403, "domain"},
		{"email_verified missing", func(op *fakeOP) { op.mutate = func(c map[string]any) { delete(c, "email_verified") } }, 403, "domain"},
		{"email missing", func(op *fakeOP) { op.mutate = func(c map[string]any) { delete(c, "email") } }, 403, "domain"},
		{"disallowed domain", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["email"] = "bob@example.com" } }, 403, "domain"},
		{"lookalike domain", func(op *fakeOP) { op.mutate = func(c map[string]any) { c["email"] = "bob@vocdoni.org.example.com" } }, 403, "domain"},
		{"token endpoint error", func(op *fakeOP) { op.tokenStatus = http.StatusBadRequest }, 403, "exchange"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			authURL, state := h.login("/")
			code, st := h.op.authorize(authURL)
			h.op.mu.Lock()
			c.setup(h.op)
			h.op.mu.Unlock()
			res := h.do("GET", "/auth/callback?code="+code+"&state="+st, "", state)
			if res.StatusCode != c.status {
				t.Fatalf("status %d, want %d", res.StatusCode, c.status)
			}
			if c.code != "" {
				if got := errorCode(t, res); got != c.code {
					t.Fatalf("code %q, want %q", got, c.code)
				}
				if cookieNamed(res, SessionCookie) != nil {
					t.Fatal("refused callback set a session cookie")
				}
			}
			if sc := cookieNamed(res, StateCookie); sc == nil || sc.MaxAge >= 0 {
				t.Fatal("state cookie not cleared")
			}
		})
	}
}

func TestStateRefusals(t *testing.T) {
	h := newHarness(t, nil)
	authURL, state := h.login("/")
	code, st := h.op.authorize(authURL)
	other := &http.Cookie{Name: StateCookie, Value: h.a.keys.seal(StateCookie, marshalPayload(statePayload{State: "x", Nonce: "y", CodeVerifier: "z", ReturnTo: "/", Iat: time.Now().Unix()}))}
	cases := []struct {
		name   string
		query  string
		cookie *http.Cookie
	}{
		{"state mismatch", "code=" + code + "&state=wrong", state},
		{"state param missing", "code=" + code, state},
		{"state cookie missing", "code=" + code + "&state=" + st, nil},
		{"state cookie from another login", "code=" + code + "&state=" + st, other},
		{"session cookie value as state", "code=" + code + "&state=" + st, &http.Cookie{Name: StateCookie, Value: h.a.keys.seal(SessionCookie, []byte(`{}`))}},
	}
	for _, c := range cases {
		res := h.do("GET", "/auth/callback?"+c.query, "", c.cookie)
		if res.StatusCode != 403 || errorCode(t, res) != "state" {
			t.Fatalf("%s: status %d", c.name, res.StatusCode)
		}
		if sc := cookieNamed(res, StateCookie); sc == nil || sc.MaxAge >= 0 {
			t.Fatalf("%s: state cookie not cleared", c.name)
		}
	}
	h.advance(601 * time.Second)
	res := h.do("GET", "/auth/callback?code="+code+"&state="+st, "", state)
	if res.StatusCode != 403 || errorCode(t, res) != "state" {
		t.Fatalf("expired state cookie: %d", res.StatusCode)
	}
}

func TestProviderErrorNotReflected(t *testing.T) {
	h := newHarness(t, nil)
	_, state := h.login("/")
	st := h.stateValue(state)
	res := h.do("GET", "/auth/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state="+st, "text/html", state)
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 403 || !strings.Contains(string(body), "Error code: provider") || strings.Contains(string(body), "script") || strings.Contains(string(body), "access_denied") {
		t.Fatalf("provider error page: %d %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
}

// stateValue decrypts a state cookie (test helper) to read its state.
func (h *harness) stateValue(c *http.Cookie) string {
	pt, ok := h.a.keys.open(StateCookie, c.Value)
	if !ok {
		h.t.Fatal("cannot open state cookie")
	}
	var st statePayload
	_ = json.Unmarshal(pt, &st)
	return st.State
}

func TestOpenRedirectReturnTo(t *testing.T) {
	for _, v := range []string{"//evil.com", "/\\evil.com", "https://evil.com", "/\t/evil.com", "evil.com", "", "\\\\evil.com", "/%0d%0a",
		"/\u2028x", "/a/../b", "/x\\y"} {
		h := newHarness(t, nil)
		res := h.signIn(v)
		want := "/"
		if v == "/%0d%0a" {
			want = "/%0d%0a" // percent-encoded stays a harmless relative path
		}
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Fatalf("return_to %q: %d -> %q", v, res.StatusCode, res.Header.Get("Location"))
		}
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t, nil)
	session := cookieNamed(h.signIn("/"), SessionCookie)
	res := h.do("GET", "/auth/logout", "text/html", session)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "POST" || cookieNamed(res, SessionCookie) != nil {
		t.Fatalf("GET logout: %d allow=%q", res.StatusCode, res.Header.Get("Allow"))
	}
	// Cross-site or header-less POSTs are refused and keep the session.
	for _, c := range []struct {
		name string
		hdr  map[string]string
	}{
		{"no headers", nil},
		{"cross-site origin", map[string]string{"Origin": "https://evil.example"}},
		{"null origin", map[string]string{"Origin": "null"}},
		{"cross-site fetch metadata", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"origin decides when both are present", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"}},
	} {
		res := h.post("/auth/logout", c.hdr, session)
		if res.StatusCode != http.StatusForbidden || errorCode(t, res) != "origin" || cookieNamed(res, SessionCookie) != nil {
			t.Fatalf("%s: %d %v", c.name, res.StatusCode, res.Cookies())
		}
	}
	for _, hdr := range []map[string]string{
		{"Origin": "https://mytool.example"},
		{"Sec-Fetch-Site": "same-origin"},
		{"Origin": "https://mytool.example", "Sec-Fetch-Site": "same-origin"},
	} {
		res := h.post("/auth/logout", hdr, session)
		if c := cookieNamed(res, SessionCookie); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" || c == nil || c.MaxAge >= 0 {
			t.Fatalf("POST logout %v: %d %q %+v", hdr, res.StatusCode, res.Header.Get("Location"), c)
		}
	}
}

func TestIssuerDownAtStart(t *testing.T) {
	op := newFakeOP(t)
	op.setDown(true)
	h := newHarness(t, func(c *Config) { c.Issuer = op.issuer(); c.HTTPClient = op.srv.Client() })
	h.op = op
	res := h.do("GET", "/auth/login", "application/json")
	if res.StatusCode != http.StatusServiceUnavailable || errorCode(t, res) != "sso_unavailable" {
		t.Fatalf("login with issuer down: %d", res.StatusCode)
	}
	op.setDown(false)
	if res := h.do("GET", "/auth/login", ""); res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login during backoff: %d, want 503 without contacting the issuer", res.StatusCode)
	}
	h.advance(2 * time.Second)
	if res := h.do("GET", "/auth/login", ""); res.StatusCode != http.StatusFound {
		t.Fatalf("login after recovery: %d", res.StatusCode)
	}
	if res := h.do("GET", "/auth/login", "text/html"); res.StatusCode != http.StatusFound {
		t.Fatalf("second login: %d", res.StatusCode)
	}
}

func TestLimiter(t *testing.T) {
	var calls int
	h := newHarness(t, func(c *Config) { c.Limiter = func(*http.Request) bool { calls++; return false } })
	for _, p := range []string{"/auth/login", "/auth/callback?state=x&code=y"} {
		res := h.do("GET", p, "")
		if res.StatusCode != http.StatusTooManyRequests || errorCode(t, res) != "rate_limited" {
			t.Fatalf("%s: %d", p, res.StatusCode)
		}
	}
	if calls != 2 {
		t.Fatalf("limiter called %d times", calls)
	}
}

func TestMethods(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/auth/login", "/auth/callback"} {
		if res := h.do("POST", p, ""); res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != "GET" {
			t.Fatalf("POST %s: %d", p, res.StatusCode)
		}
	}
	if res := h.do("GET", "/auth/other", ""); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown auth route: %d", res.StatusCode)
	}
}
