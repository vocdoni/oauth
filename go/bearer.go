// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// ErrUnavailable means the provider could not be reached (metadata or keys),
// so the token was not judged. Require answers 503 for it.
var ErrUnavailable = errors.New("vocauth: identity provider unavailable")

// ErrInvalidToken means the access token is not acceptable for this resource.
var ErrInvalidToken = errors.New("vocauth: invalid access token")

// ErrForbidden means the token is valid but its user is not admitted; a new
// token will not help, so Require answers 403 rather than 401.
var ErrForbidden = errors.New("vocauth: user not admitted")

var errNoEmail = errors.New("no e-mail claim")

// refetchEvery bounds JWKS refetches and unavailable warnings: forged tokens
// cannot make this kit hit the provider more than once per interval.
const refetchEvery = 5 * time.Second

// BearerConfig configures a Bearer, the resource-server side for APIs and MCP
// servers that accept `Authorization: Bearer` access tokens. Issuer and
// Audiences are required; the admission fields match Config.
type BearerConfig struct {
	Issuer string // e.g. https://oauth.vocdoni.org

	// Audiences are the client ids whose tokens are accepted: a token's aud
	// claim must contain one of them.
	Audiences []string

	AllowedDomains []string // as Config.AllowedDomains
	AllowedEmails  []string // as Config.AllowedEmails

	// Insecure allows an http:// issuer and resource metadata URL (localhost only).
	Insecure bool

	// ResourceMetadataURL, when set, is advertised as resource_metadata in
	// WWW-Authenticate so clients can find ProtectedResourceMetadata (RFC 9728).
	ResourceMetadataURL string

	// HTTPClient is used for discovery and JWKS requests (default: 10 s timeout).
	HTTPClient *http.Client
	// Logger receives provider errors (default slog.Default()).
	Logger *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// normalize validates c and returns a copy with defaults applied.
func (c BearerConfig) normalize() (BearerConfig, error) {
	var errs []error
	errs = append(errs, checkURL("Issuer", c.Issuer, c.Insecure))
	if len(c.Audiences) == 0 {
		errs = append(errs, errors.New("vocauth: at least one audience is required"))
	}
	auds := make([]string, 0, len(c.Audiences))
	for _, a := range c.Audiences {
		a = strings.TrimSpace(a)
		if a == "" || hasControl(a) {
			errs = append(errs, fmt.Errorf("vocauth: invalid audience %q", a))
			continue
		}
		auds = append(auds, a)
	}
	if c.ResourceMetadataURL != "" {
		errs = append(errs, checkURL("ResourceMetadataURL", c.ResourceMetadataURL, c.Insecure))
		if strings.ContainsAny(c.ResourceMetadataURL, "\"\\") || hasControl(c.ResourceMetadataURL) {
			errs = append(errs, errors.New("vocauth: ResourceMetadataURL must not contain quotes, backslashes or control characters"))
		}
	}
	domains, emails, admissionErr := normalizeAdmission(c.AllowedDomains, c.AllowedEmails)
	errs = append(errs, admissionErr)
	c.Audiences, c.AllowedDomains, c.AllowedEmails = auds, domains, emails
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
		return BearerConfig{}, err
	}
	return c, nil
}

// Bearer verifies access tokens issued by the provider and implements Require
// for them. It performs no network I/O until the first token arrives.
type Bearer struct {
	cfg  BearerConfig
	disc *discovery

	mu       sync.Mutex // guards verifier
	verifier *oidc.IDTokenVerifier

	lastWarn atomic.Int64 // UnixNano of the last unavailable warning
}

// NewBearer validates cfg. The provider is discovered on the first token, and
// retried with backoff while it is down, as Auth does for logins.
func NewBearer(cfg BearerConfig) (*Bearer, error) {
	c, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	disc := &discovery{issuer: c.Issuer, client: c.HTTPClient, now: c.Now}
	return &Bearer{cfg: c, disc: disc}, nil
}

// verifierFor returns the ID token verifier, discovering the provider on first use.
func (b *Bearer) verifierFor() (*oidc.IDTokenVerifier, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.verifier != nil {
		return b.verifier, nil
	}
	p, err := b.disc.provider()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.Claims(&meta); err != nil || meta.JWKSURI == "" {
		return nil, fmt.Errorf("%w: discovery has no jwks_uri", ErrUnavailable)
	}
	keys := &remoteKeys{url: meta.JWKSURI, client: b.cfg.HTTPClient, now: b.cfg.Now, every: refetchEvery}
	// Audience is checked against Audiences in Verify; go-oidc only knows one
	// ClientID. Expiry gets the same 60 s skew as Auth.
	b.verifier = oidc.NewVerifier(b.cfg.Issuer, keys, &oidc.Config{
		SkipClientIDCheck: true,
		Now:               func() time.Time { return b.cfg.Now().Add(-clockSkew) },
	})
	return b.verifier, nil
}

// verifyOutcome travels in the context of one Verify call, so a key-fetch
// failure can be told apart from a bad token without shared state.
type verifyOutcome struct{ unavailable bool }

type outcomeKey struct{}

// Verify checks an access token's signature, issuer, expiry and audience and
// admits its user as sign-in does; errors wrap ErrUnavailable, ErrForbidden or
// ErrInvalidToken.
func (b *Bearer) Verify(ctx context.Context, rawToken string) (User, error) {
	v, err := b.verifierFor()
	if err != nil {
		return User{}, err
	}
	var outcome verifyOutcome
	idt, err := v.Verify(context.WithValue(ctx, outcomeKey{}, &outcome), rawToken)
	if err != nil {
		if outcome.unavailable {
			return User{}, fmt.Errorf("%w: key fetch failed", ErrUnavailable)
		}
		return User{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !slices.ContainsFunc(idt.Audience, func(a string) bool { return slices.Contains(b.cfg.Audiences, a) }) {
		return User{}, fmt.Errorf("%w: audience not accepted", ErrInvalidToken)
	}
	if idt.Subject == "" {
		return User{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&claims); err != nil {
		return User{}, fmt.Errorf("%w: claims undecodable", ErrInvalidToken)
	}
	if claims.Email == "" {
		return User{}, fmt.Errorf("%w: %w", ErrForbidden, errNoEmail)
	}
	email, ok := admit(claims.Email, claims.EmailVerified, b.cfg.AllowedDomains, b.cfg.AllowedEmails)
	if !ok {
		return User{}, ErrForbidden
	}
	return User{Subject: idt.Subject, Email: email, Name: claims.Name}, nil
}

// Require puts the token's User in the context; it answers 401 unauthenticated
// or invalid_token, 403 forbidden for a user not admitted, and 503 sso_unavailable.
func (b *Bearer) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, present := bearerToken(r)
		if !present {
			b.challenge(w, "", "")
			writeJSON(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		u, err := b.Verify(r.Context(), raw)
		switch {
		case errors.Is(err, ErrUnavailable):
			b.warnUnavailable(err)
			writeJSON(w, http.StatusServiceUnavailable, "sso_unavailable")
		case errors.Is(err, ErrForbidden):
			scope := ""
			if errors.Is(err, errNoEmail) {
				scope = "openid email"
			}
			b.challenge(w, "insufficient_scope", scope)
			writeJSON(w, http.StatusForbidden, "forbidden")
		case err != nil:
			// The reason is not logged: it is attacker-controlled and may name the user.
			b.challenge(w, "invalid_token", "")
			writeJSON(w, http.StatusUnauthorized, "invalid_token")
		default:
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
		}
	})
}

// warnUnavailable logs at most once per refetchEvery, so an outage does not
// write one line per request.
func (b *Bearer) warnUnavailable(err error) {
	now := b.cfg.Now().UnixNano()
	last := b.lastWarn.Load()
	if now-last < int64(refetchEvery) || !b.lastWarn.CompareAndSwap(last, now) {
		return
	}
	b.cfg.Logger.Warn("vocauth: bearer token not verified", "err", err)
}

// challenge sets WWW-Authenticate (RFC 6750 section 3, RFC 9728 section 5.1).
// errCode and scope are included when non-empty.
func (b *Bearer) challenge(w http.ResponseWriter, errCode, scope string) {
	params := `realm="vocdoni"`
	if errCode != "" {
		params += `, error="` + errCode + `"`
	}
	if scope != "" {
		params += `, scope="` + scope + `"`
	}
	if b.cfg.ResourceMetadataURL != "" {
		params += `, resource_metadata="` + b.cfg.ResourceMetadataURL + `"`
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+params)
}

// bearerToken returns the token of an `Authorization: Bearer` header; the
// scheme is case-insensitive. Any other header counts as no token.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// remoteKeys is the provider's JWKS as a go-oidc KeySet. go-oidc refetches on
// every miss, so forged tokens would cost one fetch each; here a refetch happens
// at most once per every interval, only for unknown kids.
type remoteKeys struct {
	url    string
	client *http.Client
	now    func() time.Time
	every  time.Duration

	mu       sync.RWMutex // guards the fields below
	keys     []jose.JSONWebKey
	fetched  time.Time
	fetchErr error // outcome of the last fetch, nil on success

	fetchMu sync.Mutex // serialises fetches
}

var (
	errFetch = errors.New("JWKS fetch failed")
	errNoKey = errors.New("no key verifies the token")
)

// VerifySignature implements oidc.KeySet.
func (k *remoteKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errNoKey
	}
	kid := jws.Signatures[0].Header.KeyID
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	// Kids are random per key and never reused, so a known kid with a bad
	// signature is a forgery: no refetch.
	if k.knows(kid) {
		return nil, errNoKey
	}
	payload, err := k.refetch(ctx, jws, kid)
	if errors.Is(err, errFetch) {
		if o, ok := ctx.Value(outcomeKey{}).(*verifyOutcome); ok {
			o.unavailable = true
		}
	}
	return payload, err
}

func (k *remoteKeys) knows(kid string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.ContainsFunc(k.keys, func(key jose.JSONWebKey) bool { return key.KeyID == kid })
}

func (k *remoteKeys) verify(jws *jose.JSONWebSignature, kid string) ([]byte, bool) {
	k.mu.RLock()
	keys := k.keys
	k.mu.RUnlock()
	for i := range keys {
		if kid != "" && keys[i].KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(&keys[i]); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// refetch makes at most one JWKS request per every interval. Within the
// interval it repeats the last fetch's outcome instead of asking again.
func (k *remoteKeys) refetch(ctx context.Context, jws *jose.JSONWebSignature, kid string) ([]byte, error) {
	k.fetchMu.Lock()
	defer k.fetchMu.Unlock()
	// Another goroutine may have refreshed the keys while this one waited.
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	k.mu.RLock()
	fetched, fetchErr := k.fetched, k.fetchErr
	k.mu.RUnlock()
	now := k.now()
	if now.Sub(fetched) < k.every {
		if fetchErr != nil {
			return nil, fetchErr
		}
		return nil, errNoKey
	}
	err := k.fetch(context.WithoutCancel(ctx))
	if err != nil {
		err = fmt.Errorf("%w: %w", errFetch, err)
	}
	k.mu.Lock()
	k.fetched, k.fetchErr = now, err
	k.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if payload, ok := k.verify(jws, kid); ok {
		return payload, nil
	}
	return nil, errNoKey
}

// maxJWKSBytes caps a JWKS response; a real key set is a few kilobytes.
const maxJWKSBytes = 1 << 20

func (k *remoteKeys) fetch(ctx context.Context) error {
	// A caller-supplied client may have no timeout; fetchMu must not wait forever.
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // read-only body: a close error changes nothing
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS answered %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return err
	}
	k.mu.Lock()
	k.keys = set.Keys
	k.mu.Unlock()
	return nil
}

// protectedResource is the RFC 9728 metadata document.
type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	BearerMethods        []string `json:"bearer_methods_supported"`
	Scopes               []string `json:"scopes_supported,omitempty"`
}

// ProtectedResourceMetadata serves the RFC 9728 document naming issuer as the
// authorization server. Mount it at the well-known path that
// BearerConfig.ResourceMetadataURL points to.
func ProtectedResourceMetadata(resource string, issuer string, scopes []string) http.Handler {
	meta := protectedResource{
		Resource:             resource,
		AuthorizationServers: []string{issuer},
		BearerMethods:        []string{"header"},
		Scopes:               scopes,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})
}
