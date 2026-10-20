// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxAge is the session lifetime when Config.MaxAge is zero.
	DefaultMaxAge = 12 * time.Hour
	// MaxMaxAge is the longest accepted Config.MaxAge.
	MaxMaxAge = 7 * 24 * time.Hour
	// KeySize is the length in bytes of every cookie key (AES-256).
	KeySize = 32

	clockSkew      = 60 * time.Second
	stateMaxAge    = 600 * time.Second
	httpTimeout    = 10 * time.Second
	maxReturnToLen = 2048
)

// DefaultAllowedDomains applies when neither AllowedDomains nor AllowedEmails is set.
var DefaultAllowedDomains = []string{"vocdoni.org"}

// Config configures an Auth. Issuer, ClientID, ClientSecret, RedirectURL and
// CookieKeys are required; everything else is optional.
type Config struct {
	Issuer       string // e.g. https://oauth.vocdoni.org
	ClientID     string
	ClientSecret string
	RedirectURL  string // absolute URL of GET /auth/callback, registered at the provider

	// CookieKeys are 32-byte AES-256 keys. CookieKeys[0] encrypts; any key
	// decrypts, so rotation is staged by prepending a new key.
	CookieKeys [][]byte

	// AllowedDomains admits every verified e-mail whose domain (after the last
	// "@") equals one of these, case-insensitively. AllowedEmails admits exact
	// addresses. When both are empty, AllowedDomains is DefaultAllowedDomains.
	AllowedDomains []string
	AllowedEmails  []string

	// MaxAge is the absolute session lifetime (default 12h, at most 7 days).
	MaxAge time.Duration

	// Insecure drops the Secure cookie attribute and allows http:// issuer and
	// redirect URLs. Only for localhost development.
	Insecure bool

	// Limiter, when set, is called for GET /auth/login and GET /auth/callback;
	// returning false answers 429 {"error":"rate_limited"}. Default: allow.
	Limiter func(*http.Request) bool

	// HTTPClient is used for discovery, JWKS and token requests
	// (default: a client with a 10 s timeout).
	HTTPClient *http.Client
	// Logger receives refusal reasons and provider errors (default slog.Default()).
	Logger *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// normalize validates c and returns a copy with defaults applied.
func (c Config) normalize() (Config, error) {
	var errs []error
	errs = append(errs, checkURL("Issuer", c.Issuer, c.Insecure))
	errs = append(errs, checkURL("RedirectURL", c.RedirectURL, c.Insecure))
	if c.ClientID == "" || strings.ContainsAny(c.ClientID, "\"\\") || hasControl(c.ClientID) {
		errs = append(errs, errors.New("vocauth: ClientID is required and must not contain quotes, backslashes or control characters"))
	}
	if c.ClientSecret == "" {
		errs = append(errs, errors.New("vocauth: ClientSecret is required"))
	}
	if len(c.CookieKeys) == 0 {
		errs = append(errs, errors.New("vocauth: at least one cookie key is required"))
	}
	for i, k := range c.CookieKeys {
		if len(k) != KeySize {
			errs = append(errs, fmt.Errorf("vocauth: CookieKeys[%d] is %d bytes, want %d", i, len(k), KeySize))
		}
	}
	switch {
	case c.MaxAge == 0:
		c.MaxAge = DefaultMaxAge
	case c.MaxAge < time.Second || c.MaxAge > MaxMaxAge:
		errs = append(errs, fmt.Errorf("vocauth: MaxAge must be between 1s and %s", MaxMaxAge))
	}
	domains := make([]string, 0, len(c.AllowedDomains))
	for _, d := range c.AllowedDomains {
		d = asciiLower(strings.TrimSpace(d))
		if d == "" || strings.Contains(d, "@") {
			errs = append(errs, fmt.Errorf("vocauth: invalid allowed domain %q", d))
			continue
		}
		domains = append(domains, d)
	}
	emails := make([]string, 0, len(c.AllowedEmails))
	for _, e := range c.AllowedEmails {
		e = asciiLower(strings.TrimSpace(e))
		if at := strings.LastIndexByte(e, '@'); at <= 0 || at == len(e)-1 {
			errs = append(errs, fmt.Errorf("vocauth: invalid allowed e-mail %q", e))
			continue
		}
		emails = append(emails, e)
	}
	if len(domains) == 0 && len(emails) == 0 {
		domains = append(domains, DefaultAllowedDomains...)
	}
	c.AllowedDomains, c.AllowedEmails = domains, emails
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: httpTimeout}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return c, nil
}

func checkURL(field, raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("vocauth: %s must be an absolute URL without query or fragment", field)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !insecure) {
		return fmt.Errorf("vocauth: %s must use https (http only with Insecure)", field)
	}
	return nil
}

// ParseCookieKeys parses a comma-separated list of base64 (standard or URL
// alphabet, padding optional) 32-byte keys, e.g. the output of
// `openssl rand -base64 32`. The first key encrypts.
func ParseCookieKeys(s string) ([][]byte, error) {
	var keys [][]byte
	for i, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		part = strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(part, "="))
		k, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || len(k) != KeySize {
			return nil, fmt.Errorf("vocauth: cookie key %d is not base64 of %d bytes", i, KeySize)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// asciiLower lower-cases A-Z only, so both kits agree byte for byte.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
