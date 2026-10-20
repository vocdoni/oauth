// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Cookie names (also the AES-GCM additional data of their values).
const (
	SessionCookie = "vocauth_session"
	StateCookie   = "vocauth_state"
)

const (
	nonceSize      = 12
	tagSize        = 16
	maxCookieValue = 4096
)

// sessionPayload and statePayload field order is part of the cookie format:
// both kits serialise exactly these keys in this order.
type sessionPayload struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

type statePayload struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	ReturnTo     string `json:"return_to"`
	Iat          int64  `json:"iat"`
}

// keyring seals with keys[0] and opens with any key whose id matches.
//
// Cookie value = base64url-nopad(key_id(1) || nonce(12) || AES-256-GCM
// ciphertext||tag), AAD = cookie name. key_id = SHA-256(key)[0]: it names the
// key independently of its position in the list, so prepending a new key
// does not orphan cookies sealed with the old one.
type keyring struct {
	ids   []byte
	aeads []cipher.AEAD
}

func newKeyring(keys [][]byte) (*keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("vocauth: no cookie keys")
	}
	k := &keyring{}
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		k.ids = append(k.ids, keyID(key))
		k.aeads = append(k.aeads, aead)
	}
	return k, nil
}

func keyID(key []byte) byte {
	sum := sha256.Sum256(key)
	return sum[0]
}

// sealWithNonce is deterministic for a given nonce (fixtures); seal draws one.
func (k *keyring) sealWithNonce(name string, plaintext, nonce []byte) string {
	out := make([]byte, 0, 1+nonceSize+len(plaintext)+tagSize)
	out = append(out, k.ids[0])
	out = append(out, nonce...)
	out = k.aeads[0].Seal(out, nonce, plaintext, []byte(name))
	return base64.RawURLEncoding.EncodeToString(out)
}

func (k *keyring) seal(name string, plaintext []byte) string {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return k.sealWithNonce(name, plaintext, nonce)
}

func (k *keyring) open(name, value string) ([]byte, bool) {
	if value == "" || len(value) > maxCookieValue {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < 1+nonceSize+tagSize {
		return nil, false
	}
	id, nonce, ct := raw[0], raw[1:1+nonceSize], raw[1+nonceSize:]
	for i, aead := range k.aeads {
		if k.ids[i] != id {
			continue
		}
		if pt, err := aead.Open(nil, nonce, ct, []byte(name)); err == nil {
			return pt, true
		}
	}
	return nil, false
}

// marshalPayload is JSON without HTML escaping and without a trailing
// newline, matching JavaScript's JSON.stringify for the cookie payloads.
func marshalPayload(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // payloads are plain structs of strings and integers
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}
