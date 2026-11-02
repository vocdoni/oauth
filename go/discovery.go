// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

var errBackoff = errors.New("vocauth: discovery is backing off after a failure")

// discovery fetches provider metadata on first use. A failure is retried on a
// later call after an exponential backoff (1 s doubling to 1 min); while backing
// off it fails fast without touching the network.
type discovery struct {
	issuer string
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex // guards the fields below
	p       *oidc.Provider
	nextTry time.Time
	backoff time.Duration
}

func (d *discovery) provider() (*oidc.Provider, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.p != nil {
		return d.p, nil
	}
	now := d.now()
	if now.Before(d.nextTry) {
		return nil, errBackoff
	}
	// go-oidc keeps this context as the configuration of the provider's
	// long-lived remote key set (JWKS refetched on unknown kid), so it must
	// not be a request context; the HTTP client carries the timeout.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), d.client), d.issuer)
	if err != nil {
		if d.backoff == 0 {
			d.backoff = minBackoff
		} else {
			d.backoff = min(2*d.backoff, maxBackoff)
		}
		d.nextTry = now.Add(d.backoff)
		return nil, err
	}
	d.p = p
	return p, nil
}
