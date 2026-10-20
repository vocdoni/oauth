// SPDX-License-Identifier: AGPL-3.0-only

package vocauth

import (
	"regexp"
	"slices"
	"strings"
)

var returnToRE = regexp.MustCompile(`^/[^/\\]`)

// sanitizeReturnTo keeps relative paths only: it must match ^/[^/\\], hold no
// ASCII control character (browsers strip tab/CR/LF, so "/\t/evil" would
// become "//evil") and be at most 2048 bytes; anything else becomes "/".
func sanitizeReturnTo(s string) string {
	if len(s) > maxReturnToLen || !returnToRE.MatchString(s) || hasControl(s) {
		return "/"
	}
	return s
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
