// SPDX-License-Identifier: AGPL-3.0-only

// Command example is a minimal Go tool behind Vocdoni sign-in.
//
// Local development against `docker compose up` in the repository root:
//
//	export OAUTH_ISSUER=http://localhost:5556 OAUTH_CLIENT_ID=dev \
//	  OAUTH_CLIENT_SECRET=dev-client-secret OAUTH_INSECURE=1 \
//	  OAUTH_REDIRECT_URL=http://localhost:8080/auth/callback \
//	  OAUTH_COOKIE_KEYS="$(openssl rand -base64 32)"
//	go run .
//
// then open http://localhost:8080 and sign in as dev@vocdoni.org.
package main

import (
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	vocauth "github.com/vocdoni/oauth/go"
)

func main() {
	keys, err := vocauth.ParseCookieKeys(os.Getenv("OAUTH_COOKIE_KEYS"))
	if err != nil {
		log.Fatal(err)
	}
	h, err := newHandler(vocauth.Config{
		Issuer:       envOr("OAUTH_ISSUER", "https://oauth.vocdoni.org"),
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
		CookieKeys:   keys,
		Insecure:     os.Getenv("OAUTH_INSECURE") == "1",
		Limiter:      newLimiter(20, time.Minute).allow,
	})
	if err != nil {
		log.Fatal(err)
	}
	addr := envOr("ADDR", "localhost:8080")
	log.Printf("listening on http://%s", addr)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// newHandler wires the kit: /auth/* are the sign-in routes, everything else
// requires a session.
func newHandler(cfg vocauth.Config) (http.Handler, error) {
	a, err := vocauth.New(cfg)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", a.Routes())
	mux.Handle("/", a.Require(http.HandlerFunc(home)))
	return mux, nil
}

func home(w http.ResponseWriter, r *http.Request) {
	u, _ := vocauth.FromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><title>Example</title>
<p>Signed in as %s (%s).</p>
<form method="post" action="/auth/logout"><button>Sign out</button></form>
<p>Signing out here does not sign you out of Google.</p>
`, html.EscapeString(u.Name), html.EscapeString(u.Email))
}

// limiter allows n sign-in requests per client IP per window (fixed window).
// Tools behind a proxy should key on the proxy's client IP header instead.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	start  time.Time
	counts map[string]int
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, counts: map[string]int{}}
}

func (l *limiter) allow(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.start) > l.window {
		l.start, l.counts = now, map[string]int{}
	}
	l.counts[ip]++
	return l.counts[ip] <= l.n
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
