// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"regexp"
	"slices"
	"strings"
)

var returnToRE = regexp.MustCompile(`^/[^/\\]`)

// sanitizeReturnTo keeps same-origin relative paths only; anything else
// becomes "/". The value must:
//   - be at most 2048 bytes and hold only printable ASCII (browsers strip
//     tab/CR/LF, so "/\t/evil" would become "//evil", and a Fetch Location
//     header cannot hold characters above U+00FF);
//   - match ^/[^/\\] and hold no backslash anywhere (browsers read "\" as "/");
//   - have no "." or ".." segment in its path (before "?" or "#"), counting
//     the percent-encoded forms browsers treat the same ("%2e", ".%2e", ...).
//
// The Node kit applies the same rules byte for byte.
func sanitizeReturnTo(s string) string {
	if len(s) > maxReturnToLen || !returnToRE.MatchString(s) || !printableASCII(s) ||
		strings.ContainsRune(s, '\\') || hasDotSegment(s) {
		return "/"
	}
	return s
}

// printableASCII reports whether s holds only bytes 0x20-0x7e.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasDotSegment reports whether the path of s (up to the first "?" or "#")
// has a "." or ".." segment, literal or percent-encoded (%2e, any case).
func hasDotSegment(s string) bool {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	for seg := range strings.SplitSeq(s, "/") {
		if d := strings.ReplaceAll(asciiLower(seg), "%2e", "."); d == "." || d == ".." {
			return true
		}
	}
	return false
}

// admit applies the admission rules to verified ID-token claims and returns
// the lower-cased e-mail when the user may sign in.
func admit(email string, verified bool, domains, emails []string) (string, bool) {
	if email == "" || !verified {
		return "", false
	}
	e := asciiLower(email)
	if slices.Contains(emails, e) {
		return e, true
	}
	at := strings.LastIndexByte(e, '@')
	if at <= 0 || at == len(e)-1 {
		return "", false
	}
	if slices.Contains(domains, e[at+1:]) {
		return e, true
	}
	return "", false
}
