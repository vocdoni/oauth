// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vocauth "github.com/vocdoni/oauth/go"
)

func TestHandlerWiring(t *testing.T) {
	h, err := newHandler(vocauth.Config{
		Issuer:       "http://127.0.0.1:1", // nothing listens: the process must still start
		ClientID:     "dev",
		ClientSecret: "dev-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		CookieKeys:   [][]byte{make([]byte, 32)},
		Insecure:     true,
		HTTPClient:   &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/login?return_to=%2F" {
		t.Fatalf("GET /: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("login with the issuer down: %d", w.Code)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	r := httptest.NewRequest("GET", "/auth/login", nil)
	got := []bool{l.allow(r), l.allow(r), l.allow(r)}
	if !got[0] || !got[1] || got[2] {
		t.Fatalf("limiter = %v, want allow, allow, refuse", got)
	}
}
