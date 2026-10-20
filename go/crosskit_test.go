// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestCookieFixturesNode opens, re-serialises and re-seals every cookie the
// Node kit produced (node.json, written by `npm run fixtures` in node/), and
// checks that both kits produced the very same cases from the same inputs.
func TestCookieFixturesNode(t *testing.T) {
	nodePath := filepath.Join("testdata", "cookies", "node.json")
	verifyFixtureFile(t, nodePath)

	read := func(p string) fixtureFile {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f fixtureFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	g, n := read(filepath.Join("testdata", "cookies", "go.json")), read(nodePath)
	if g.Generator != "go" || n.Generator != "node" {
		t.Fatalf("generators: %q, %q", g.Generator, n.Generator)
	}
	g.Generator, n.Generator = "", ""
	if !reflect.DeepEqual(g, n) {
		t.Fatal("go.json and node.json differ: the kits do not produce byte-identical cookies")
	}
}
