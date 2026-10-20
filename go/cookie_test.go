// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/cookies/go.json")

// Cross-kit cookie fixtures. Both kits generate the same file from the same
// fixed keys, nonces and payloads (go.json here, node.json from `npm run
// fixtures` in node/); each kit verifies every case of both files.
type fixtureFile struct {
	Format    string           `json:"format"`
	Generator string           `json:"generator"`
	Keys      []string         `json:"keys"` // base64 (std), 32 bytes each; the opening keyring
	Cases     []fixtureCase    `json:"cases"`
	Invalid   []fixtureInvalid `json:"invalid"`
}

type fixtureCase struct {
	Name    string `json:"name"`
	Cookie  string `json:"cookie"`
	SealKey int    `json:"sealKey"` // index into Keys of the sealing key
	Nonce   string `json:"nonce"`   // hex, 12 bytes
	Payload string `json:"payload"` // exact plaintext JSON
	Value   string `json:"value"`   // cookie value
}

type fixtureInvalid struct {
	Name   string `json:"name"`
	Cookie string `json:"cookie"`
	Value  string `json:"value"`
}

func seqKey(start byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = start + byte(i)
	}
	return k
}

func seqNonce(start byte) []byte {
	n := make([]byte, nonceSize)
	for i := range n {
		n[i] = start + byte(i)
	}
	return n
}

func buildFixture(t *testing.T) fixtureFile {
	t.Helper()
	keyA, keyB, keyC := seqKey(0x00), seqKey(0x20), seqKey(0x40)
	f := fixtureFile{
		Format:    "vocauth-cookie-v1",
		Generator: "go",
		Keys:      []string{base64.StdEncoding.EncodeToString(keyA), base64.StdEncoding.EncodeToString(keyB)},
	}
	session := marshalPayload(sessionPayload{Sub: "CiQxMjM0NTY3ODkw", Email: "alice@vocdoni.org", Name: "Alice Example", Iat: 1760954400, Exp: 1760997600})
	unicode := marshalPayload(sessionPayload{Sub: "u-2", Email: "nuria@vocdoni.org", Name: "Núria Ñúñez & <Co> \"Q\" \\ é", Iat: 1760954400, Exp: 1760997600})
	state := marshalPayload(statePayload{State: "c3RhdGUtc3RhdGUtc3RhdGUtc3RhdGUtc3RhdGUtc3Q", Nonce: "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm8", CodeVerifier: "dmVyaWZpZXItdmVyaWZpZXItdmVyaWZpZXItdmVyaWZp", ReturnTo: "/docs?x=1&y=%2F", Iat: 1760954400})
	add := func(name, cookie string, sealKey int, nonce []byte, payload []byte) string {
		kr, err := newKeyring([][]byte{[][]byte{keyA, keyB}[sealKey]})
		if err != nil {
			t.Fatal(err)
		}
		v := kr.sealWithNonce(cookie, payload, nonce)
		f.Cases = append(f.Cases, fixtureCase{Name: name, Cookie: cookie, SealKey: sealKey, Nonce: hex.EncodeToString(nonce), Payload: string(payload), Value: v})
		return v
	}
	sessionValue := add("session", SessionCookie, 0, seqNonce(0x80), session)
	add("state", StateCookie, 0, seqNonce(0x90), state)
	add("session-rotated-key", SessionCookie, 1, seqNonce(0xa0), session)
	add("session-unicode", SessionCookie, 0, seqNonce(0xb0), unicode)

	krC, _ := newKeyring([][]byte{keyC})
	raw, _ := base64.RawURLEncoding.DecodeString(sessionValue)
	raw[len(raw)/2] ^= 0x01
	f.Invalid = []fixtureInvalid{
		{Name: "tampered", Cookie: SessionCookie, Value: base64.RawURLEncoding.EncodeToString(raw)},
		{Name: "wrong-cookie-name", Cookie: StateCookie, Value: sessionValue},
		{Name: "unknown-key", Cookie: SessionCookie, Value: krC.sealWithNonce(SessionCookie, session, seqNonce(0xc0))},
		{Name: "truncated", Cookie: SessionCookie, Value: sessionValue[:30]},
		{Name: "not-base64url", Cookie: SessionCookie, Value: "a+b/c=="},
		{Name: "empty", Cookie: SessionCookie, Value: ""},
		{Name: "too-long", Cookie: SessionCookie, Value: strings.Repeat("A", maxCookieValue+1)},
	}
	return f
}

func encodeFixture(t *testing.T, f fixtureFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// verifyFixtureFile checks every case of a fixture file produced by either kit.
func verifyFixtureFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if f.Format != "vocauth-cookie-v1" || len(f.Cases) == 0 || len(f.Invalid) == 0 {
		t.Fatalf("%s: unexpected fixture header or empty cases", path)
	}
	var keys [][]byte
	for _, s := range f.Keys {
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	ring, err := newKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		pt, ok := ring.open(c.Cookie, c.Value)
		if !ok || string(pt) != c.Payload {
			t.Errorf("%s/%s: open = %q, %v; want %q", f.Generator, c.Name, pt, ok, c.Payload)
		}
		var re []byte
		switch c.Cookie {
		case SessionCookie:
			var p sessionPayload
			if err := json.Unmarshal([]byte(c.Payload), &p); err != nil {
				t.Fatal(err)
			}
			re = marshalPayload(p)
		case StateCookie:
			var p statePayload
			if err := json.Unmarshal([]byte(c.Payload), &p); err != nil {
				t.Fatal(err)
			}
			re = marshalPayload(p)
		default:
			t.Fatalf("%s/%s: unknown cookie %q", f.Generator, c.Name, c.Cookie)
		}
		if string(re) != c.Payload {
			t.Errorf("%s/%s: payload re-serialised as %s", f.Generator, c.Name, re)
		}
		nonce, _ := hex.DecodeString(c.Nonce)
		sealer, _ := newKeyring([][]byte{keys[c.SealKey]})
		if got := sealer.sealWithNonce(c.Cookie, []byte(c.Payload), nonce); got != c.Value {
			t.Errorf("%s/%s: seal = %s; want %s (not byte-identical)", f.Generator, c.Name, got, c.Value)
		}
	}
	for _, c := range f.Invalid {
		if _, ok := ring.open(c.Cookie, c.Value); ok {
			t.Errorf("%s/invalid %s: opened, want failure", f.Generator, c.Name)
		}
	}
}

func TestCookieFixturesGo(t *testing.T) {
	path := filepath.Join("testdata", "cookies", "go.json")
	want := encodeFixture(t, buildFixture(t))
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test -run TestCookieFixturesGo -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run go test -run TestCookieFixturesGo -update", path)
	}
	verifyFixtureFile(t, path)
}

func TestKeyringRotationAndTamper(t *testing.T) {
	oldKey, newKey := seqKey(1), seqKey(2)
	before, _ := newKeyring([][]byte{oldKey})
	v := before.seal(SessionCookie, []byte(`{"x":1}`))

	after, _ := newKeyring([][]byte{newKey, oldKey})
	if pt, ok := after.open(SessionCookie, v); !ok || string(pt) != `{"x":1}` {
		t.Fatalf("rotated keyring cannot open old cookie: %q %v", pt, ok)
	}
	dropped, _ := newKeyring([][]byte{newKey})
	if _, ok := dropped.open(SessionCookie, v); ok {
		t.Fatal("cookie opened after its key was removed")
	}
	if _, ok := after.open(StateCookie, v); ok {
		t.Fatal("session value accepted as state cookie (AAD not bound)")
	}
	if a, b := before.seal(SessionCookie, []byte("p")), before.seal(SessionCookie, []byte("p")); a == b {
		t.Fatal("two seals produced the same value: nonce reuse")
	}
}

func TestParseCookieKeys(t *testing.T) {
	a, b := seqKey(0), seqKey(0x20)
	in := base64.StdEncoding.EncodeToString(a) + " , " + base64.RawURLEncoding.EncodeToString(b)
	keys, err := ParseCookieKeys(in)
	if err != nil || len(keys) != 2 || !bytes.Equal(keys[0], a) || !bytes.Equal(keys[1], b) {
		t.Fatalf("ParseCookieKeys = %v, %v", keys, err)
	}
	for _, bad := range []string{"", "abc", base64.StdEncoding.EncodeToString(make([]byte, 16)), "!!!!"} {
		if _, err := ParseCookieKeys(bad); err == nil {
			t.Errorf("ParseCookieKeys(%q) accepted", bad)
		}
	}
}
