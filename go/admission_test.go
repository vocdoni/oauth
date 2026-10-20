// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"strings"
	"testing"
)

func TestSanitizeReturnTo(t *testing.T) {
	keep := []string{"/a", "/docs?x=1&y=%2F", "/ui/", "/%2F%2Fevil.com"}
	for _, s := range keep {
		if got := sanitizeReturnTo(s); got != s {
			t.Errorf("sanitizeReturnTo(%q) = %q, want unchanged", s, got)
		}
	}
	drop := []string{"", "/", "//evil.com", "/\\evil.com", "https://evil.com", "evil.com",
		"/\t/evil.com", "/\n/evil.com", "/\r\n/x", "\\/evil.com", "/x\x7f", " /a",
		"/" + strings.Repeat("a", maxReturnToLen)}
	for _, s := range drop {
		if got := sanitizeReturnTo(s); got != "/" {
			t.Errorf("sanitizeReturnTo(%q) = %q, want /", s, got)
		}
	}
}

func TestAdmit(t *testing.T) {
	domains := []string{"vocdoni.org"}
	emails := []string{"guest@example.com"}
	cases := []struct {
		email    string
		verified bool
		want     string
		ok       bool
	}{
		{"alice@vocdoni.org", true, "alice@vocdoni.org", true},
		{"Alice@VOCDONI.org", true, "alice@vocdoni.org", true},
		{"alice@vocdoni.org", false, "", false},
		{"", true, "", false},
		{"bob@example.com", true, "", false},
		{"guest@example.com", true, "guest@example.com", true},
		{"GUEST@example.com", true, "guest@example.com", true},
		{"alice@sub.vocdoni.org", true, "", false},
		{"alice@vocdoni.org.evil.com", true, "", false},
		{"a@b@vocdoni.org", true, "a@b@vocdoni.org", true},
		{"@vocdoni.org", true, "", false},
		{"vocdoni.org", true, "", false},
	}
	for _, c := range cases {
		got, ok := admit(c.email, c.verified, domains, emails)
		if got != c.want || ok != c.ok {
			t.Errorf("admit(%q, %v) = %q, %v; want %q, %v", c.email, c.verified, got, ok, c.want, c.ok)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{
		Issuer: "https://oauth.vocdoni.org", ClientID: "mytool", ClientSecret: "s",
		RedirectURL: "https://mytool.vocdoni.io/auth/callback", CookieKeys: [][]byte{seqKey(0)},
	}
	c, err := good.normalize()
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxAge != DefaultMaxAge || len(c.AllowedDomains) != 1 || c.AllowedDomains[0] != "vocdoni.org" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	only := good
	only.AllowedEmails = []string{"Guest@Example.com"}
	if c, _ := only.normalize(); len(c.AllowedDomains) != 0 || c.AllowedEmails[0] != "guest@example.com" {
		t.Fatalf("AllowedEmails alone must not add the default domain: %+v", c)
	}
	bad := []func(*Config){
		func(c *Config) { c.Issuer = "" },
		func(c *Config) { c.Issuer = "http://oauth.vocdoni.org" },
		func(c *Config) { c.RedirectURL = "/auth/callback" },
		func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.ClientID = `a"b` },
		func(c *Config) { c.ClientSecret = "" },
		func(c *Config) { c.CookieKeys = nil },
		func(c *Config) { c.CookieKeys = [][]byte{make([]byte, 16)} },
		func(c *Config) { c.MaxAge = MaxMaxAge + 1 },
		func(c *Config) { c.MaxAge = -1 },
		func(c *Config) { c.AllowedDomains = []string{"a@b"} },
		func(c *Config) { c.AllowedEmails = []string{"nobody"} },
	}
	for i, mutate := range bad {
		c := good
		mutate(&c)
		if _, err := c.normalize(); err == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
	insecure := good
	insecure.Insecure = true
	insecure.Issuer, insecure.RedirectURL = "http://localhost:5556", "http://localhost:8080/auth/callback"
	if _, err := insecure.normalize(); err != nil {
		t.Fatalf("http URLs with Insecure rejected: %v", err)
	}
}
